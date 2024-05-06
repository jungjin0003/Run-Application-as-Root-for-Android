ANDROID_NDK_ROOT=
ANDROID_API_VERSION=21

CC=$(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/windows-x86_64/bin/clang
CFLAGS=-target aarch64-linux-android$(ANDROID_API_VERSION)
LDFLAGS=$(CFLAGS)

all: injector libhookzygote.so

injector: injector.o

libhookzygote.so: libhookzygote.o
	$(CC) $(LDFLAGS) -shared $^ -o $@

clean:
	rm -f injector libhookzygote.so *.o