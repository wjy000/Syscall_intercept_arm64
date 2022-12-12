# Syscall_intercept_arm64
介绍见看雪文章：https://bbs.pediy.com/thread-271921.htm
前言
大概一年前写的吧，arm64版本已开源：https://github.com/onesss19/Syscall_intercept_arm64（求star
hook svc的方案已经有好几种，前几天有个大佬开源的Frida-Seccomp，罗哥开源的krhook，内存搜索+inlinehook，还有一些大佬没开源的核武器
这个工具是基于ptrace实现的，开发涉及到的关键API都是直接参考官方文档https://man7.org/linux/man-pages/man2/ptrace.2.html

##### 使用
```java
void show_helper(){
    printf(
            "\nSyscall_intercept -z <zygote_pid> -n <appname> -p <target_pid>\n"
            "options:\n"
            "\t-z <zygote_pid> : pid of zygote\n"
            "\t-t <appname> : application name\n"
            "\t-p <target_pid>: pid of application\n"
    );
}
```
支持spawn模式和attach模式,
- spawn模式
打开目标app后运行指令
```
Syscall_intercept -z zygote_pid -n package_name
```

- attach模式
打开目标app后运行指令
```
Syscall_intercept -p target_pid
```


##### 原理
主要就是依赖于ptrace的这个参数：
```
// the tracee to be stopped at the next entry to or exit from a system call
ptrace(PTRACE_SYSCALL, wait_pid, 0, 0);
```
spawn模式的原理是ptrace到zygote进程，然后跟踪zygote进程的fork系统调用，如果fork出来的新进程是指定包名的app，那么detach掉zygote进程，进而跟踪目标app进程的系统调用

attach模式的原理是直接ptrace目标app进程的所有线程

##### 功能
大体功能和strace类似，实现原理也是一样的，主要是多了hook的能力
起初是想在strace的基础上改，源码框架没看太懂，转而自己写了个小玩具（逃
以拦截openat系统调用为例，运行结果：

对应源码：
```java
void openat_item(pid_t pid,user_pt_regs regs){
    char        filename[256];
    char        path[256];
    uint32_t    filenamelength=0;
 
    get_addr_path(pid,regs.ARM_x1,path);
    if(strstr(path,"/data/app")!=0 || strstr(path,"[anon:libc_malloc]")!=0){
        getdata(pid,regs.ARM_x1,filename,256);
        if(strcmp(filename,"/dev/ashmem")!=0){
            print_register_enter(regs,pid,(char*)"__NR_openat",regs.ARM_x8);
            printf("filename: %s\n",filename);
            printf("path: %s\n",path);
            if(strcmp(filename,"/proc/sys/kernel/random/boot_id")==0){
                char tmp[256]="/data/local/tmp/boot_id";
                filenamelength=strlen(tmp)+1;
                putdata(pid,regs.ARM_x1,tmp,filenamelength);
                getdata(pid,regs.ARM_x1,filename,256);
                printf("changed filename: %s\n",filename);
            }
        }
    }
}
```

##### 编译
用ndk里面自带的clang++编译即可
```
~/Library/Android/sdk/ndk-bundle/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang++ -target aarch64-linux-android21 Syscall_intercept_arm64.cpp Syscall_item_enter_arm64.cpp -o Syscall_intercept_arm64 -static-libstdc++
```

TODO
只是一个能跑的玩具，主要是把思路抛出来，后续可以适配更多的系统调用，可以添加栈回溯等等功能~