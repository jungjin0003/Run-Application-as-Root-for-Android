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

#define INIT_PID        1
#define MAX_PID         32768

#define ARM             0
#define AARCH64         1

#ifdef __arm__
#define REGS            regs
#define RETURN_VALUE    ARM_r0
#define SYSCALL_NUMBER  ARM_r7
#define CHECK_RETURNED  uregs[12]
#define STACK_POINTER   ARM_sp
#define ARG0            ARM_r0
#define ARG1            ARM_r1
#define ARG2            ARM_r2
#elif __aarch64__
#define PTRACE_GETREGS  PTRACE_GETREGSET
#define PTRACE_SETREGS  PTRACE_SETREGSET
#define REGS            iovecs
#define RETURN_VALUE    regs[0]
#define SYSCALL_NUMBER  regs[8]
#define CHECK_RETURNED  regs[28]
#define STACK_POINTER   sp
#define ARG0            regs[0]
#define ARG1            regs[1]
#define ARG2            regs[2]
#endif

#define PTRACE(r, p, a, d) internal_ptrace(r, p, a, d)

int get_zygote_pid(int arch)
{
    char fname[64];
    char data[64];
    int zygote_pid = -1;
    FILE *fp = NULL;

    for (int i = 0; i < MAX_PID && zygote_pid == -1; i++)
    {
        snprintf(fname, sizeof(fname), "/proc/%d/cmdline", i);
        fp = fopen(fname, "r");

        if (fp == NULL)
            continue;

        if (fgets(data, sizeof(data), fp) != NULL)
        {
            if (strcmp(data, arch ? "zygote64" : "zygote") == NULL)
                zygote_pid = i;
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
        PTRACE(PTRACE_POKEDATA, pid, (char *)addr + i, (void *)*(long *)(buf + i));

        if (i >= strlen(buf))
            break;
    }
}

void *monitor_new_zygote(void *arg)
{
#ifdef __arm__
    #define ARCHITECTURE ARM + 1
#elif __aarch64__
    #define ARCHITECTURE AARCH64 + 1
#endif
    int bSuccessLD_PRELOAD = 0;
    char zygote_path[32];
    char line[256];
    pid_t prev_zygote_pid[ARCHITECTURE];
    pid_t cur_zygote_pid[ARCHITECTURE];

    while (1)
    {
        sleep(1);

        for (int i = 0; i < ARCHITECTURE; i++)
            cur_zygote_pid[i] = get_zygote_pid(i);

        if (ARCHITECTURE - 1 == ARM ? cur_zygote_pid[ARM] == -1 : (cur_zygote_pid[ARM] == -1 || cur_zygote_pid[AARCH64] == -1))
            continue;

        if (ARCHITECTURE - 1 == ARM ? prev_zygote_pid[ARM] == cur_zygote_pid[ARM] : (prev_zygote_pid[ARM] == cur_zygote_pid[ARM] && prev_zygote_pid[AARCH64] == cur_zygote_pid[AARCH64]))
            continue;

        prev_zygote_pid[ARM] = cur_zygote_pid[ARM];
#ifdef __aarch64__
        prev_zygote_pid[AARCH64] = cur_zygote_pid[AARCH64];
#endif

        for (int i = 0; i < ARCHITECTURE; i++)
        {
            memset(zygote_path, (int)NULL, sizeof(zygote_path));
            sprintf(zygote_path, "/proc/%d/maps", cur_zygote_pid[i]);

            FILE *fp = fopen(zygote_path, "r");

            if (fp == NULL)
            {
                printf("[-] Failed to open %s : %s\n", zygote_path, strerror(errno));
                continue;
            }

            while (fgets(line, sizeof(line), fp) != NULL)
            {
                if (strstr(line, "libhookzygote"))
                {
                    bSuccessLD_PRELOAD = 1;
                    break;
                }
            }
            
            fclose(fp);
            
            if (bSuccessLD_PRELOAD == 0)
                break;
        }

        if (bSuccessLD_PRELOAD)
            break;
        else if (arg == NULL)
        {
            kill(cur_zygote_pid[ARM], SIGKILL);
#ifdef __aarch64__
            kill(cur_zygote_pid[AARCH64], SIGKILL);
#endif
        }
    }

    exit(0);
}

int generate_new_zygote(pid_t zygote_pid)
{
#ifdef __arm__
    struct user_regs regs;
#elif __aarch64__
    struct user_regs_struct regs;
    struct iovec iovecs;
    iovecs.iov_base = &regs;
    iovecs.iov_len = sizeof(regs);
#endif

    siginfo_t sig;

    if (PTRACE(PTRACE_ATTACH, INIT_PID, (void *)1, NULL) < 0)
    {
        puts("[-] PTRACE_ATTACH failed to init process");
        return -1;
    }

    kill(zygote_pid, SIGKILL);
    puts("[*] Sending a SIGKILL signal to zygote");

    pthread_t thread_t;
    pthread_create(&thread_t, NULL, monitor_new_zygote, NULL);

    while (1)
    {
        memset(&sig, (int)NULL, sizeof(siginfo_t));

        if (!PTRACE(PTRACE_GETSIGINFO, INIT_PID, (void *)0, &sig) && sig.si_signo == SIGCHLD && PTRACE(PTRACE_SYSCALL, INIT_PID, (void *)NT_PRSTATUS, (void *)SIGCHLD) < 0)
        {
            puts("[-] Can't detect signal or syscall");
            return -1;
        }

        memset(&regs, (int)NULL, sizeof(regs));

        if (PTRACE(PTRACE_GETREGS, INIT_PID, (void *)NT_PRSTATUS, &REGS) < 0)
        {
            puts("[-] Can't get process register information");
            return -1;
        }

        if (regs.SYSCALL_NUMBER == SYS_clone && regs.RETURN_VALUE <= MAX_PID && zygote_pid != regs.RETURN_VALUE)
        {
            zygote_pid = regs.RETURN_VALUE;

            if (fork() == 0)
            {
                pthread_create(&thread_t, NULL, monitor_new_zygote, 1);
                printf("[*] Found a new process : %ld\n", regs.RETURN_VALUE);
                zygote_pid = regs.RETURN_VALUE;
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

void manipulation_zygote_envp(pid_t zygote_pid)
{
#ifdef __arm__
    #define REGS regs
    struct user_regs regs;
#elif __aarch64__
    #define REGS iovecs
    struct user_regs_struct regs;
    struct iovec iovecs;
    iovecs.iov_base = &regs;
    iovecs.iov_len = sizeof(regs);
#endif

    if (PTRACE(PTRACE_ATTACH, zygote_pid, (void *)1, NULL) < 0)
    {
        printf("[-] New zygote64 attach failed\n");
        return;
    }

    while (1)
    {
        PTRACE(PTRACE_SYSCALL, zygote_pid, (void *)1, NULL);
        PTRACE(PTRACE_GETREGS, zygote_pid, (void *)NT_PRSTATUS, &REGS);

        if (regs.SYSCALL_NUMBER == SYS_execve)
        {
            char filename[100];
            read_string(zygote_pid, (void *)regs.ARG0, filename, sizeof(filename));

            printf("[*] detect execve : %s\n", filename);
#ifdef __arm__
            if (strcmp(filename, "/system/bin/app_process"))
                break;
#elif __aarch64__
            if (strcmp(filename, "/system/bin/app_process32") && strcmp(filename, "/system/bin/app_process64"))
                break;
#endif
            int envc = 0, injected = 0;
            for (int *envp = (int *)PTRACE(PTRACE_PEEKDATA, zygote_pid, (void *)(regs.ARG2 + envc * sizeof(void *)), NULL); envp; envp = (int *)PTRACE(PTRACE_PEEKDATA, zygote_pid, (void *)(regs.ARG2 + ++envc * sizeof(void *)), NULL))
            {
                char *env = malloc(4096);
                memset(env, (int)NULL, 4096);

                read_string(zygote_pid, envp, env, 4096);

                if (strncmp("LD_PRELOAD", env, 10) == 0)
                {
                    PTRACE(PTRACE_POKEDATA, zygote_pid, (void *)(regs.ARG2 + envc * sizeof(void *)), (void *)(regs.STACK_POINTER - 2048));
                    strcat(env, ":libhookzygote.so");

                    write_string(zygote_pid, (void *)(regs.STACK_POINTER - 2048), env);
                    injected = 1;
                }

                free(env);
            }

            if (!injected)
            {
                printf("[*] Injecting LD_PRELOAD into zygote...\n");
                char *envp = (char *)regs.ARG2;
                char *new_envp = (char *)((regs.STACK_POINTER - 2048) & ~0xF);

                for (int i = 0; i < envc; i++)
                {
                    long env = PTRACE(PTRACE_PEEKDATA, zygote_pid, (void *)(envp + i * sizeof(void *)), NULL);
                    PTRACE(PTRACE_POKEDATA, zygote_pid, (void *)(new_envp + i * sizeof(void *)), (void *)env);
                }

                PTRACE(PTRACE_POKEDATA, zygote_pid, new_envp + envc * sizeof(void *), new_envp + (envc + 2) * sizeof(void *));
                PTRACE(PTRACE_POKEDATA, zygote_pid, new_envp + (envc + 1) * sizeof(void *), NULL);
                write_string(zygote_pid, new_envp + (envc + 2) * sizeof(void *), "LD_PRELOAD=libhookzygote.so");

                regs.ARG2 = (unsigned long)new_envp;
                PTRACE(PTRACE_SETREGS, zygote_pid, (void *)NT_PRSTATUS, &REGS);
                PTRACE(PTRACE_GETREGS, zygote_pid, (void *)NT_PRSTATUS, &REGS);
            }

            break;
        }

        PTRACE(PTRACE_SYSCALL, zygote_pid, (void *)1, NULL);
    }

    PTRACE(PTRACE_DETACH, zygote_pid, NULL, NULL);
}

int main()
{
    pid_t zygote_pid = get_zygote_pid(ARM);

    puts("[*] Get the zygote pid...");

    if (zygote_pid == -1)
    {
        puts("[-] Not found zygote process...");
        return -1;
    }

    zygote_pid = generate_new_zygote(zygote_pid);
    manipulation_zygote_envp(zygote_pid);

    return 0;
}