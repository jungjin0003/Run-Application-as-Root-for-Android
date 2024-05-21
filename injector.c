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
#define IS_RETURNED     1
#define RETURN_VALUE    ARM_r0
#define SYSCALL_NUMBER  ARM_r7
#define CHECK_RETURNED  uregs[12]
#define STACK_POINTER   ARM_sp
#define ARG0            ARM_r0
#define ARG2            ARM_r2
#elif __aarch64__
#define PTRACE_GETREGS  PTRACE_GETREGSET
#define REGS            iovecs
#define IS_RETURNED     0
#define RETURN_VALUE    regs[0]
#define SYSCALL_NUMBER  regs[8]
#define CHECK_RETURNED  regs[28]
#define STACK_POINTER   sp
#define ARG0            regs[0]
#define ARG2            regs[2]
#endif

#define PTRACE(r, p, a, d) internal_ptrace(r, p, a, d)

int status;
#ifdef __aarch64__
void handler(int sig)
{
    if (sig == SIGUSR1)
        status = 1;
    else if (sig == SIGUSR2)
        status = 2;
}
#endif
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
        cur_zygote_pid = get_zygote_pid(status);

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
            if (strstr(line, "libhookzygote"))
            {
                bSuccessLD_PRELOAD = 1;
                break;
            }
        }

        fclose(fp);
#ifdef __arm__
        if (bSuccessLD_PRELOAD)
            break;
#elif __aarch64__
        if (bSuccessLD_PRELOAD && arg == NULL)
            break;

        if (bSuccessLD_PRELOAD && arg && status == 2)
            break;
#endif
        if (!bSuccessLD_PRELOAD && arg)
            kill(cur_zygote_pid, SIGKILL);
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

        if (PTRACE(PTRACE_GETREGSET, INIT_PID, NT_PRSTATUS, &REGS) < 0)
        {
            puts("[-] Can't get process register information");
            return -1;
        }

        if (regs.SYSCALL_NUMBER == SYS_clone && regs.CHECK_RETURNED == IS_RETURNED && regs.RETURN_VALUE <= MAX_PID && zygote_pid != regs.RETURN_VALUE)
        {
            zygote_pid = regs.RETURN_VALUE;

            if (fork() == 0)
            {
                pthread_create(&thread_t, NULL, monitor_new_zygote, NULL);
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

    if (PTRACE(PTRACE_ATTACH, zygote_pid, 1, NULL) < 0)
    {
        printf("[-] New zygote64 attach failed\n");
        return;
    }

    while (1)
    {
        PTRACE(PTRACE_SYSCALL, zygote_pid, 1, NULL);
        PTRACE(PTRACE_GETREGS, zygote_pid, NT_PRSTATUS, &REGS);

        if (regs.SYSCALL_NUMBER == SYS_execve)
        {
            char filename[100];
            read_string(zygote_pid, regs.ARG0, filename, sizeof(filename));

            printf("[*] detect execve : %s\n", filename);
#ifdef __arm__
            if (strcmp(filename, "/system/bin/app_process"))
                break;
#elif __aarch64__
            if (strcmp(filename, "/system/bin/app_process32") && status != 1)
                break;
            else if (strcmp(filename, "/system/bin/app_process64") && status != 0)
                break;

            kill(getppid(), status ? SIGUSR2 : SIGUSR1);
#endif
            for (int i = 0, *envp = PTRACE(PTRACE_PEEKDATA, zygote_pid, regs.ARG2 + i * sizeof(void *), NULL); envp; envp = PTRACE(PTRACE_PEEKDATA, zygote_pid, regs.ARG2 + i * sizeof(void *), NULL))
            {
                char *env = malloc(1024);
                memset(env, NULL, 1024);

                read_string(zygote_pid, envp, env, 1024);
                printf("[*] envp[%d] : %s\n", i++, env);

                if (strncmp("LD_PRELOAD", env, 10) == 0)
                {
                    PTRACE(PTRACE_POKEDATA, zygote_pid, regs.ARG2 + (i - 1) * sizeof(void *), regs.STACK_POINTER - 2048);
                    strcat(env, status ? ":/data/local/tmp/libhookzygote64.so" : ":/data/local/tmp/libhookzygote32.so");

                    write_string(zygote_pid, regs.STACK_POINTER - 2048, env);
                }

                free(env);
            }

            break;
        }

        PTRACE(PTRACE_SYSCALL, zygote_pid, 1, NULL);
    }

    PTRACE(PTRACE_DETACH, zygote_pid, NULL, NULL);
}

int main()
{
#ifdef __aarch64__
    signal(SIGUSR1, handler);
    signal(SIGUSR2, handler);
#endif
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