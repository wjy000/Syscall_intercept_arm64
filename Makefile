# export PATH=.../Android/Sdk/ndk/24.0.8215888/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

all:
	~/Library/Android/sdk/ndk-bundle/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang++ -target aarch64-linux-android21 Syscall_intercept_arm64.cpp Syscall_item_enter_arm64.cpp -o Syscall_intercept_arm64 -static-libstdc++
	adb -s 59def0e3 push Syscall_intercept_arm64 /data/local/tmp
	adb -s 59def0e3 shell chmod 777 /data/local/tmp/Syscall_intercept_arm64