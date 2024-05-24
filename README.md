# Run Application as Root for Android : RARA
A library that helps you run Android applications on root

## Supported Android Versions
The Android versions that have confirmed the current behavior are as follows
|       Arch | Version           |
|-----------:|:------------------|
|     ARMv7a | 7.1 (Nougat)      |
|    AArch64 | 7.1 (Nougat)      |

## Getting Started
Please follow the following procedure to use RARA \
[Click here to download compiled files](https://github.com/jungjin0003/Run-Application-as-Root-for-Android/releases/latest) and if you're donw downloading it, [proceed from here](#rara-install)

### Compile Requisities
 - Android NDK version 21 (Errors may occur in later version, Someone tell me how should change the code)

### Setting ANDROID_NDK_ROOT
Setting ANDROID_NDK_ROOT variable in Makefile. Default Android API Version is 21 but you can change it \
If you aren't using Windows or Linux, change the path of the CC variable
```makefile
ANDROID_NDK_ROOT=
ANDROID_API_VERSION=21

ifeq ($(OS), Windows_NT)
CC=$(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/windows-x86_64/bin/clang
else
CC=$(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
endif                                           ~~~~~~~~~~~~
                                                Change to your OS
```

### Let's Build!!
```shell
$ make
```

### RARA Install
If the adb path is not registered in the PATH environment variable, please set the entire path of adb in the registration or ADB environment variable \
If you download and proceed with the compiled file, proceed with the contents of `Release file` \
\
Windows
```
$ make install
or
$ set ADB=C:\PATH\TO\YOURS\adb.exe
$ make install
```
Linux
```
$ make install
or
$ ADB=/PATH/TO/YOURS/adb make install
```
Release file
```
$ adb root
$ adb shell mkdir /data/local/tmp
armv7a====================================
$ adb push injector /data/local/tmp
$ adb shell mount -o rw,remount /system
$ adb push libhookzygote.so /system/lib
$ adb shell mount -o ro.remount /system
==========================================
aarch64===================================
$ adb push injector /data/local/tmp
$ adb shell mount -o rw,remount /system
$ adb push libhookzygote32.so /system/lib
$ adb push libhookzygote.so /system/lib64
$ adb shell mount -o ro.remount /system
==========================================
```

### Change SELinux mode
To inject LD_PRELOAD into the zygote, SELinux mode must be disable or permissive. Need to check and change the SELinux mode
```
$ adb root
$ adb shell
// Connect to Android shell
# getenforce
Enforcing
# setenforce 0
# getenforce
Permissive
```

### Injection libhookzygote.so
```
# cd /data/local/tmp
# ./injector
[*] Get the zygote64 pid...
[*] Sending a SIGKILL signal to zygote
[*] Found a new process : 29324
[*] detect execve : /system/bin/cameraserver
[*] Found a new process : 29324
[*] Found a new process : 29324
[*] Found a new process : 29324
[*] Found a new process : 29336
[*] Found a new process : 29339
[*] detect execve : /system/bin/mediaserver
[*] Found a new process : 29342
[*] detect execve : /system/bin/netd
[*] Found a new process : 29353
[*] Found a new process : 29361
[*] detect execve : /system/bin/rild
[*] Found a new process : 29369
[*] Found a new process : 29379
[*] Found a new process : 29475
[*] detect execve : /system/bin/cameraserver
[*] Found a new process : 29478
[*] detect execve : /system/bin/app_process64
[*] envp[0] : PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin
[*] envp[1] : DOWNLOAD_CACHE=/data/cache
[*] envp[2] : ANDROID_BOOTLOGO=1
[*] envp[3] : ANDROID_ROOT=/system
[*] envp[4] : ANDROID_ASSETS=/system/app
[*] envp[5] : ANDROID_DATA=/data
[*] envp[6] : ANDROID_STORAGE=/storage
[*] envp[7] : EXTERNAL_STORAGE=/sdcard
[*] envp[8] : ASEC_MOUNTPOINT=/mnt/asec
[*] envp[9] : BOOTCLASSPATH=/system/framework/core-oj.jar:/system/framework/core-libart.jar:/system/framework/conscrypt.jar:/system/framework/okhttp.jar:/system/framework/core-junit.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/telephony-common.jar:/system/framework/voip-common.jar:/system/framework/ims-common.jar:/system/framework/apache-xml.jar:/system/framework/org.apache.http.legacy.boot.jar:/system/framework/telephony-ext.jar
[*] envp[10] : SYSTEMSERVERCLASSPATH=/system/framework/org.cyanogenmod.platform.jar:/system/framework/org.cyanogenmod.hardware.jar:/system/framework/services.jar:/system/framework/ethernet-service.jar:/system/framework/wifi-service.jar
[*] envp[11] : LD_PRELOAD=libsigchain.so
[*] envp[12] : ANDROID_CACHE=/cache
[*] envp[13] : TERMINFO=/system/etc/terminfo
[*] envp[14] : MC_AUTH_TOKEN_PATH=/efs
[*] envp[15] : ANDROID_SOCKET_zygote=9
```

### Write the package name
Write the package name of the application to run as root in a file named root_app.list in the `/data/local/tmp` directory
```
# pwd
/data/local/tmp
# ls
injector    root_app.list
# cat root_app.list
org.qtproject.example.PoC_libpcap
org.qtproject.example.PoC_TcpPort80
```

## Authors
 - [CrazyHacker](https://github.com/jungjin0003) - **JungJin Kim** - <admin@crazyhacker.kr>