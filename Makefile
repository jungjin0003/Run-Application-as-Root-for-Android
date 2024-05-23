ANDROID_NDK_ROOT = 
ANDROID_API_VERSION = 21

ifeq ($(OS), Windows_NT)
CC = $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/windows-x86_64/bin/clang
else
CC = $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
endif
CFLAGS = -target aarch64-linux-android$(ANDROID_API_VERSION) -w
LDFLAGS = $(CFLAGS)

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