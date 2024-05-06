#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <pthread.h>
#include <elf.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define INIT_PID 1
#define MAX_PID 32768
#define PTRACE(r, p, a, d) internal_ptrace(r, p, a, d)

int get_zygote_pid()
{
    char fname[64];
    char status[64];
    int i, zygote_pid;
    FILE *fp = NULL;

    zygote_pid = -1;

    for (i = 0; i < MAX_PID; i++)
    {
        snprintf(fname, sizeof(fname), "/proc/%d/cmdline", i);
        if ((fp = fopen(fname, "r")) == NULL)
            continue;
        if (fgets(status, sizeof(status), fp) != NULL)
        {
            if (strstr(status, "zygote64") != NULL)
            {
                zygote_pid = i;
                fclose(fp);
                break;
            }
        }
        fclose(fp);
    }
    return zygote_pid;
}

long internal_ptrace(int request, pid_t pid, void *addr, void *data)
{
    long ret, stat;

    while (1)
    {
        stat = 0;
        ret = waitpid(pid, &stat, WNOHANG);
        if ((ret == pid && WIFEXITED(stat)) || (WIFSTOPPED(stat) && !WSTOPSIG(stat)))
        {
            printf("[!] Killed Process: %d\n", pid);
            return -1;
        }

        if ((ret = ptrace(request, pid, addr, data)) != -1)
            break;
        else if (request == PTRACE_DETACH || request == PTRACE_SYSCALL || request == PTRACE_KILL)
        {
            ret = 0;
            break;
        }
    }

    return ret;
}

void read_string(pid_t pid, void *addr, char *buf, size_t count)
{
    for (int i = 0;; i += sizeof(long))
    {
        char data[sizeof(long)] = { 0 };
        *(long *)data = PTRACE(PTRACE_PEEKDATA, pid, (char *)addr + i, NULL);

        for (int j = 0; j < sizeof(long) && i + j < count; j++)
        {
            buf[i + j] = data[j];

            if (data[j] == 0x00)
                return;
        }
    }
}

void write_string(pid_t pid, void *addr, const char *buf)
{
    for (int i = 0;; i += sizeof(long))
    {
        PTRACE(PTRACE_POKEDATA, pid, (char *)addr + i, *(long *)(buf + i));

        if (i >= strlen(buf))
            break;
    }
}

void *monitor_new_zygote(void *arg)
{
    int bSuccessLD_PRELOAD = 0;
    char zygote_path[32];
    char line[256];
    pid_t prev_zygote_pid = -1;
    pid_t cur_zygote_pid = -1;

    while (1)
    {
        sleep(1);
        cur_zygote_pid = get_zygote_pid();

        if (cur_zygote_pid == -1)
            continue;

        if (prev_zygote_pid == cur_zygote_pid)
            continue;

        prev_zygote_pid = cur_zygote_pid;

        memset(zygote_path, NULL, sizeof(zygote_path));
        sprintf(zygote_path, "/proc/%d/maps", cur_zygote_pid);

        FILE *fp = fopen(zygote_path, "r");

        if (fp == NULL)
            continue;

        while (fgets(line, sizeof(line), fp) != NULL)
        {
            if (strstr(line, "libhookzygote.so"))
            {
                bSuccessLD_PRELOAD = 1;
                break;
            }
        }

        fclose(fp);

        if (bSuccessLD_PRELOAD)
            break;

        if (!bSuccessLD_PRELOAD && arg)
            kill(cur_zygote_pid, SIGKILL);
    }

    exit(0);
}

int generate_new_zygote(pid_t zygote_pid)
{
    struct user_regs_struct regs;
    struct iovec iovecs;
    iovecs.iov_base = &regs;
    iovecs.iov_len = sizeof(regs);

    siginfo_t sig;

    if (PTRACE(PTRACE_ATTACH, INIT_PID, 1, NULL) < 0)
    {
        puts("[-] PTRACE_ATTACH failed to init process");
        return -1;
    }

    kill(zygote_pid, SIGKILL);
    puts("[*] Sending a SIGKILL signal to zygote");

    pthread_t thread_t;
    pthread_create(&thread_t, NULL, monitor_new_zygote, 1);

    while (1)
    {
        memset(&sig, NULL, sizeof(siginfo_t));

        if (!PTRACE(PTRACE_GETSIGINFO, INIT_PID, 0, &sig) && sig.si_signo == SIGCHLD && PTRACE(PTRACE_SYSCALL, INIT_PID, NT_PRSTATUS, SIGCHLD) < 0)
        {
            puts("[-] Can't detect signal or syscall");
            return -1;
        }

        memset(&regs, NULL, sizeof(regs));

        if (PTRACE(PTRACE_GETREGSET, INIT_PID, NT_PRSTATUS, &iovecs) < 0)
        {
            puts("[-] Can't get process register information");
            return -1;
        }

        if (regs.regs[8] == SYS_clone && regs.regs[28] == 0 && regs.regs[0] <= MAX_PID && zygote_pid != regs.regs[0])
        {
            if (fork() == 0)
            {
                pthread_create(&thread_t, NULL, monitor_new_zygote, NULL);
                printf("[*] Found a new process : %ld\n", regs.regs[0]);
                zygote_pid = regs.regs[0];
                return zygote_pid;
            }
            else
            {
                usleep(100 * 1000);
            }
        }

        if (PTRACE(PTRACE_SYSCALL, INIT_PID, 0, NULL) < 0)
        {
            puts("[-] Can't continue syscall");
            return -1;
        }
    }

    ptrace(PTRACE_DETACH, INIT_PID, 1, NULL);

    return zygote_pid;
}

int manipulation_zygote64_envp(pid_t zygote_pid)
{
    int ret = 0;
    char LD_PRELOAD[128] = { 0 };
    struct user_regs_struct regs;
    struct iovec iovecs;
    iovecs.iov_base = &regs;
    iovecs.iov_len = sizeof(regs);

    if (PTRACE(PTRACE_ATTACH, zygote_pid, 1, NULL) < 0)
    {
        printf("[-] New zygote64 attach failed\n");
        return ret;
    }

    while (1)
    {
        PTRACE(PTRACE_SYSCALL, zygote_pid, 1, NULL);
        PTRACE(PTRACE_GETREGSET, zygote_pid, NT_PRSTATUS, &iovecs);

        if (regs.regs[8] == SYS_execve)
        {
            char filename[100];
            read_string(zygote_pid, regs.regs[0], filename, sizeof(filename));

            printf("[*] detect execve : %s\n", filename);

            if (strcmp(filename, "/system/bin/app_process64"))
                break;

            ret = 1;

            for (int i = 0, *envp = PTRACE(PTRACE_PEEKDATA, zygote_pid, regs.regs[2] + i * sizeof(void *), NULL); envp; envp = PTRACE(PTRACE_PEEKDATA, zygote_pid, regs.regs[2] + i * sizeof(void *), NULL))
            {
                char *env = malloc(1024);
                memset(env, NULL, 1024);

                read_string(zygote_pid, envp, env, 1024);
                printf("[*] envp[%d] : %s\n", i++, env);

                if (strncmp("LD_PRELOAD", env, 10) == 0)
                {
                    PTRACE(PTRACE_POKEDATA, zygote_pid, regs.regs[2] + (i - 1) * sizeof(void *), regs.sp - 2048);
                    strcat(env, ":/data/local/tmp/libhookzygote.so");

                    write_string(zygote_pid, regs.sp - 2048, env);
                }

                free(env);
            }

            break;
        }

        PTRACE(PTRACE_SYSCALL, zygote_pid, 1, NULL);
    }

    PTRACE(PTRACE_DETACH, zygote_pid, NULL, NULL);

    return ret;
}

int main()
{
    printf("PID : %d\n", getpid());

    pid_t zygote_pid = get_zygote_pid();

    puts("[*] Get the zygote64 pid...");

    if (zygote_pid == -1)
    {
        puts("[-] Not found zygote64 process...");
        return -1;
    }

    zygote_pid = generate_new_zygote(zygote_pid);
    manipulation_zygote64_envp(zygote_pid);

    return 0;
}