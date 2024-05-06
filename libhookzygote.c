#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/seccomp.h>

pid_t pid = -1;

int (*origin_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
int (*origin_setresgid)(gid_t rgid, gid_t egid, gid_t sgid);
int (*origin_prctl)(int option, ...);
int (*origin_capset)(cap_user_header_t __hdr_ptr, const cap_user_data_t __data_ptr);

void dropCapabilitiesBoundingSet()
{
    for (int i = 0; origin_prctl(PR_CAPBSET_READ, i, 0, 0, 0) >= 0; i++)
    {
        if (origin_prctl(PR_CAPBSET_DROP, i, 0, 0, 0) == -1)
        {
            printf("Failed %d\n", i);
        }
    }
}

int isRootApplication(pid_t uid)
{
    char line[512];
    FILE *package_list = fopen("/data/system/packages.list", "r");
    FILE *root_app_list = fopen("/data/local/tmp/root_app.list", "r");

    if (package_list == NULL || root_app_list == NULL)
        goto exit;

    while (fgets(line, sizeof(line), package_list) != NULL)
    {
        char root_package_name[64];
        char package_name[128];
        pid_t package_uid = -1;
        sscanf(line, "%s %d", package_name, &package_uid);

        if (package_uid == uid)
        {
            while (fgets(root_package_name, sizeof(root_package_name), root_app_list) != NULL)
            {
                if (strncmp(package_name, root_package_name, strlen(package_name)) == 0)
                {
                    fclose(package_list);
                    fclose(root_app_list);
                    return 1;
                }
            }
        }
    }

exit:
    fclose(package_list);
    fclose(root_app_list);
    
    return 0;
}

int capset(cap_user_header_t __hdr_ptr, const cap_user_data_t __data_ptr)
{
    if (pid == getpid())
        return 0;

    if (origin_capset == NULL)
        origin_capset = dlsym(RTLD_NEXT, "capset");

    return origin_capset(__hdr_ptr, __data_ptr);
}

int prctl(int option, ...)
{
    va_list args;
    va_start(args, option);

    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);

    va_end(args);

    if (option == PR_CAPBSET_DROP)
        return 0;

    if (origin_prctl == NULL)
        origin_prctl = dlsym(RTLD_NEXT, "prctl");

    return origin_prctl(option, arg2, arg3, arg4, arg5);
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (isRootApplication(ruid))
	{
        pid = getpid();
        dropCapabilitiesBoundingSet();
        return 0;
    }

	if (origin_setresuid == NULL)
		origin_setresuid = dlsym(RTLD_NEXT, "setresuid");

	return origin_setresuid(ruid, euid, suid);
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (isRootApplication(rgid))
		return 0;
	
	if (origin_setresgid == NULL)
		origin_setresgid = dlsym(RTLD_NEXT, "setresgid");

	return origin_setresgid(rgid, egid, sgid);
}
