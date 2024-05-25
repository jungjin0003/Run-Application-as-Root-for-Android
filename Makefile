ANDROID_NDK_ROOT = 
ANDROID_API_VERSION = 21

ifeq ($(OS), Windows_NT)
CC = $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/windows-x86_64/bin/clang
else
CC = $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
endif
CFLAGS = -target aarch64-linux-android$(ANDROID_API_VERSION) -w
LDFLAGS = $(CFLAGS)

ADB := $(if $(ADB), $(ADB), adb)

all: run injector libhookzygote.so

injector: injector32.o injector64.o
	$(CC) $(LDFLAGS) -m32 -o bin/armv7a/$@ injector32.o
	$(CC) $(LDFLAGS) -o bin/aarch64/$@ injector64.o

libhookzygote.so: libhookzygote32.o libhookzygote64.o
	$(CC) $(LDFLAGS) -shared -m32 -o bin/armv7a/$@ libhookzygote32.o
	$(CC) $(LDFLAGS) -shared -o bin/aarch64/$@ libhookzygote64.o
ifeq ($(OS), Windows_NT)
	@copy bin\armv7a\libhookzygote.so bin\aarch64\libhookzygote32.so
else
	@cp bin/armv7a/libhookzygote.so bin/aarch64/libhookzygote32.so
endif

%32.o: %.c
	$(CC) $(CFLAGS) -fPIC -m32 -c -o $@ $^

%64.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

install:
ifeq ($(shell $(ADB) shell "su -c whoami"), root)
	$(ADB) shell "su -c 'mount -o rw,remount /system'"
ifneq (, $(findstring arm, $(shell $(ADB) shell uname -m)))
	$(ADB) push ./bin/armv7a/injector /data/local/tmp
	$(ADB) push ./bin/armv7a/libhookzygote.so /data/local/tmp
	$(ADB) shell "su -c 'cp /data/local/tmp/libhookzygote.so /system/lib'"
	$(ADB) shell "su -c 'chmod 777 /data/local/tmp/injector'"
	$(ADB) shell "su -c 'chmod 644 /system/lib/libhookzygote.so'"
	$(ADB) shell "su -c 'rm /data/local/tmp/libhookzygote.so'"
endif
ifeq ($(shell $(ADB) shell uname -m), aarch64)
	$(ADB) push ./bin/aarch64/injector /data/local/tmp
	$(ADB) push ./bin/aarch64/libhookzygote32.so /data/local/tmp
	$(ADB) push ./bin/aarch64/libhookzygote.so /data/local/tmp
	$(ADB) shell "su -c 'cp /data/local/tmp/libhookzygote32.so /system/lib/libhookzygote.so'"
	$(ADB) shell "su -c 'cp /data/local/tmp/libhookzygote.so /system/lib64/libhookzygote.so'"
	$(ADB) shell "su -c 'chmod 777 /data/local/tmp/injector'"
	$(ADB) shell "su -c 'chmod 644 /system/lib/libhookzygote.so'"
	$(ADB) shell "su -c 'chmod 644 /system/lib64/libhookzygote.so'"
	$(ADB) shell "su -c 'rm /data/local/tmp/libhookzygote32.so /data/local/tmp/libhookzygote.so'"
endif
	$(ADB) shell "su -c 'mount -o ro,remount /system'"
else
	@echo Device is not rooting
endif

uninstall:
ifeq ($(shell $(ADB) shell "su -c whoami"), root)
	$(ADB) shell "su -c 'mount -o rw,remount /system'"
	$(ADB) shell "su -c 'rm /data/local/tmp/injector'"
	$(ADB) shell "su -c 'rm /system/lib/libhookzygote.so'"
ifeq ($(shell $(ADB) shell uname -m), aarch64)
	$(ADB) shell "su -c 'rm /system/lib64/libhookzygote.so'"
endif
	$(ADB) shell "su -c 'mount -o ro,remount /system'"
else
	@echo Device is not rooting
endif

run:
	@mkdir bin
ifeq ($(OS), Windows_NT)
	@mkdir bin\armv7a
	@mkdir bin\aarch64
else
	@mkdir bin/armv7a
	@mkdir bin/aarch64
endif

clean:
ifeq ($(OS), Windows_NT)
	rmdir /s /q .\bin
	del /q *.o
else
	rm -rf ./bin
	rm -f *.o
endif