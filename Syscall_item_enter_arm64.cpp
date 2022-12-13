#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>


#include "Syscall_arm64.h"
#include "Syscall_item_enter_arm64.h"
#include "Syscall_intercept_arm64.h"

void openat_item(pid_t pid, user_pt_regs regs) {
    char filename[256];
    char path[256];
    uint32_t filenamelength = 0;

    get_addr_path(pid, regs.ARM_x1, path);
    if (strstr(path, "/data/app") != 0 || strstr(path, "[anon:libc_malloc]") != 0) {
        getdata(pid, regs.ARM_x1, filename, 256);
        if (strcmp(filename, "/dev/ashmem") == 0)
            return;
        print_register_enter(regs, pid, (char *) "__NR_openat", regs.ARM_x8);
        printf("filename: %s\n", filename);
        printf("path: %s\n", path);
        if (strcmp(filename, "/proc/sys/kernel/random/boot_id") == 0) {
            char tmp[256] = "/data/local/tmp/boot_id";
            filenamelength = strlen(tmp) + 1;
            putdata(pid, regs.ARM_x1, tmp, filenamelength);
            getdata(pid, regs.ARM_x1, filename, 256);
            printf("changed filename: %s\n", filename);
        }
    }
}

void read_item(pid_t pid, user_pt_regs regs) {
    print_register_enter(regs, pid, (char *) "__NR_read", regs.ARM_x8);
}

void SysCall_item_enter_switch(pid_t pid, user_pt_regs regs) {
    #ifdef DEBUG
//    printf("Syscall : %llu,%s\n", regs.ARM_x8, getSyscallName(regs.ARM_x8));
    #endif
    switch (regs.ARM_x8) {
        case __NR_openat:
            openat_item(pid, regs);
            break;
        case __NR_execve:
            printf("__NR_execve\n");
            break;
        default:
//            printf("Syscall : %llu,%s\n", regs.ARM_x8, getSyscallName(regs.ARM_x8));
            break;
    }
}

//获取系统调用名称
const char *getSyscallName(long rax) {
    if (__NR_io_setup == rax) return "__NR_io_setup";
    else if (__NR_io_destroy == rax) return "__NR_io_destroy";
    else if (__NR_io_submit == rax) return "__NR_io_submit";
    else if (__NR_io_cancel == rax) return "__NR_io_cancel";
    else if (__NR_io_getevents == rax) return "__NR_io_getevents";
    else if (__NR_setxattr == rax) return "__NR_setxattr";
    else if (__NR_lsetxattr == rax) return "__NR_lsetxattr";
    else if (__NR_fsetxattr == rax) return "__NR_fsetxattr";
    else if (__NR_getxattr == rax) return "__NR_getxattr";
    else if (__NR_lgetxattr == rax) return "__NR_lgetxattr";
    else if (__NR_fgetxattr == rax) return "__NR_fgetxattr";
    else if (__NR_listxattr == rax) return "__NR_listxattr";
    else if (__NR_llistxattr == rax) return "__NR_llistxattr";
    else if (__NR_flistxattr == rax) return "__NR_flistxattr";
    else if (__NR_removexattr == rax) return "__NR_removexattr";
    else if (__NR_lremovexattr == rax) return "__NR_lremovexattr";
    else if (__NR_fremovexattr == rax) return "__NR_fremovexattr";
    else if (__NR_getcwd == rax) return "__NR_getcwd";
    else if (__NR_lookup_dcookie == rax) return "__NR_lookup_dcookie";
    else if (__NR_eventfd2 == rax) return "__NR_eventfd2";
    else if (__NR_epoll_create1 == rax) return "__NR_epoll_create1";
    else if (__NR_epoll_ctl == rax) return "__NR_epoll_ctl";
    else if (__NR_epoll_pwait == rax) return "__NR_epoll_pwait";
    else if (__NR_dup == rax) return "__NR_dup";
    else if (__NR_dup3 == rax) return "__NR_dup3";
    else if (__NR3264_fcntl == rax) return "__NR3264_fcntl";
    else if (__NR_inotify_init1 == rax) return "__NR_inotify_init1";
    else if (__NR_inotify_add_watch == rax) return "__NR_inotify_add_watch";
    else if (__NR_inotify_rm_watch == rax) return "__NR_inotify_rm_watch";
    else if (__NR_ioctl == rax) return "__NR_ioctl";
    else if (__NR_ioprio_set == rax) return "__NR_ioprio_set";
    else if (__NR_ioprio_get == rax) return "__NR_ioprio_get";
    else if (__NR_flock == rax) return "__NR_flock";
    else if (__NR_mknodat == rax) return "__NR_mknodat";
    else if (__NR_mkdirat == rax) return "__NR_mkdirat";
    else if (__NR_unlinkat == rax) return "__NR_unlinkat";
    else if (__NR_symlinkat == rax) return "__NR_symlinkat";
    else if (__NR_linkat == rax) return "__NR_linkat";
#ifdef __ARCH_WANT_RENAMEAT
        else if (__NR_renameat == rax) return "__NR_renameat";
#endif
    else if (__NR_umount2 == rax) return "__NR_umount2";
    else if (__NR_mount == rax) return "__NR_mount";
    else if (__NR_pivot_root == rax) return "__NR_pivot_root";
    else if (__NR_nfsservctl == rax) return "__NR_nfsservctl";
    else if (__NR3264_statfs == rax) return "__NR3264_statfs";
    else if (__NR3264_fstatfs == rax) return "__NR3264_fstatfs";
    else if (__NR3264_truncate == rax) return "__NR3264_truncate";
    else if (__NR3264_ftruncate == rax) return "__NR3264_ftruncate";
    else if (__NR_fallocate == rax) return "__NR_fallocate";
    else if (__NR_faccessat == rax) return "__NR_faccessat";
    else if (__NR_chdir == rax) return "__NR_chdir";
    else if (__NR_fchdir == rax) return "__NR_fchdir";
    else if (__NR_chroot == rax) return "__NR_chroot";
    else if (__NR_fchmod == rax) return "__NR_fchmod";
    else if (__NR_fchmodat == rax) return "__NR_fchmodat";
    else if (__NR_fchownat == rax) return "__NR_fchownat";
    else if (__NR_fchown == rax) return "__NR_fchown";
    else if (__NR_openat == rax) return "__NR_openat";
    else if (__NR_close == rax) return "__NR_close";
    else if (__NR_vhangup == rax) return "__NR_vhangup";
    else if (__NR_pipe2 == rax) return "__NR_pipe2";
    else if (__NR_quotactl == rax) return "__NR_quotactl";
    else if (__NR_getdents64 == rax) return "__NR_getdents64";
#define __ARCH_WANT_COMPAT_SYS_GETDENTS64
    else if (__NR3264_lseek == rax) return "__NR3264_lseek";
    else if (__NR_read == rax) return "__NR_read";
    else if (__NR_write == rax) return "__NR_write";
    else if (__NR_readv == rax) return "__NR_readv";
    else if (__NR_writev == rax) return "__NR_writev";
    else if (__NR_pread64 == rax) return "__NR_pread64";
    else if (__NR_pwrite64 == rax) return "__NR_pwrite64";
    else if (__NR_preadv == rax) return "__NR_preadv";
    else if (__NR_pwritev == rax) return "__NR_pwritev";
    else if (__NR3264_sendfile == rax) return "__NR3264_sendfile";
    else if (__NR_pselect6 == rax) return "__NR_pselect6";
    else if (__NR_ppoll == rax) return "__NR_ppoll";
    else if (__NR_signalfd4 == rax) return "__NR_signalfd4";
    else if (__NR_vmsplice == rax) return "__NR_vmsplice";
    else if (__NR_splice == rax) return "__NR_splice";
    else if (__NR_tee == rax) return "__NR_tee";
    else if (__NR_readlinkat == rax) return "__NR_readlinkat";
    else if (__NR3264_fstatat == rax) return "__NR3264_fstatat";
    else if (__NR3264_fstat == rax) return "__NR3264_fstat";
    else if (__NR_sync == rax) return "__NR_sync";
    else if (__NR_fsync == rax) return "__NR_fsync";
    else if (__NR_fdatasync == rax) return "__NR_fdatasync";
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
        else if (__NR_sync_file_range2 == rax) return "__NR_sync_file_range2";
#else
    else if (__NR_sync_file_range == rax) return "__NR_sync_file_range";
#endif
    else if (__NR_timerfd_create == rax) return "__NR_timerfd_create";
    else if (__NR_timerfd_settime == rax) return "__NR_timerfd_settime";
    else if (__NR_timerfd_gettime == rax) return "__NR_timerfd_gettime";
    else if (__NR_utimensat == rax) return "__NR_utimensat";
    else if (__NR_acct == rax) return "__NR_acct";
    else if (__NR_capget == rax) return "__NR_capget";
    else if (__NR_capset == rax) return "__NR_capset";
    else if (__NR_personality == rax) return "__NR_personality";
    else if (__NR_exit == rax) return "__NR_exit";
    else if (__NR_exit_group == rax) return "__NR_exit_group";
    else if (__NR_waitid == rax) return "__NR_waitid";
    else if (__NR_set_tid_address == rax) return "__NR_set_tid_address";
    else if (__NR_unshare == rax) return "__NR_unshare";
    else if (__NR_futex == rax) return "__NR_futex";
    else if (__NR_set_robust_list == rax) return "__NR_set_robust_list";
    else if (__NR_get_robust_list == rax) return "__NR_get_robust_list";
    else if (__NR_nanosleep == rax) return "__NR_nanosleep";
    else if (__NR_getitimer == rax) return "__NR_getitimer";
    else if (__NR_setitimer == rax) return "__NR_setitimer";
    else if (__NR_kexec_load == rax) return "__NR_kexec_load";
    else if (__NR_init_module == rax) return "__NR_init_module";
    else if (__NR_delete_module == rax) return "__NR_delete_module";
    else if (__NR_timer_create == rax) return "__NR_timer_create";
    else if (__NR_timer_gettime == rax) return "__NR_timer_gettime";
    else if (__NR_timer_getoverrun == rax) return "__NR_timer_getoverrun";
    else if (__NR_timer_settime == rax) return "__NR_timer_settime";
    else if (__NR_timer_delete == rax) return "__NR_timer_delete";
    else if (__NR_clock_settime == rax) return "__NR_clock_settime";
    else if (__NR_clock_gettime == rax) return "__NR_clock_gettime";
    else if (__NR_clock_getres == rax) return "__NR_clock_getres";
    else if (__NR_clock_nanosleep == rax) return "__NR_clock_nanosleep";
    else if (__NR_syslog == rax) return "__NR_syslog";
    else if (__NR_ptrace == rax) return "__NR_ptrace";
    else if (__NR_sched_setparam == rax) return "__NR_sched_setparam";
    else if (__NR_sched_setscheduler == rax) return "__NR_sched_setscheduler";
    else if (__NR_sched_getscheduler == rax) return "__NR_sched_getscheduler";
    else if (__NR_sched_getparam == rax) return "__NR_sched_getparam";
    else if (__NR_sched_setaffinity == rax) return "__NR_sched_setaffinity";
    else if (__NR_sched_getaffinity == rax) return "__NR_sched_getaffinity";
    else if (__NR_sched_yield == rax) return "__NR_sched_yield";
    else if (__NR_sched_get_priority_max == rax) return "__NR_sched_get_priority_max";
    else if (__NR_sched_get_priority_min == rax) return "__NR_sched_get_priority_min";
    else if (__NR_sched_rr_get_interval == rax) return "__NR_sched_rr_get_interval";
    else if (__NR_restart_syscall == rax) return "__NR_restart_syscall";
    else if (__NR_kill == rax) return "__NR_kill";
    else if (__NR_tkill == rax) return "__NR_tkill";
    else if (__NR_tgkill == rax) return "__NR_tgkill";
    else if (__NR_sigaltstack == rax) return "__NR_sigaltstack";
    else if (__NR_rt_sigsuspend == rax) return "__NR_rt_sigsuspend";
    else if (__NR_rt_sigaction == rax) return "__NR_rt_sigaction";
    else if (__NR_rt_sigprocmask == rax) return "__NR_rt_sigprocmask";
    else if (__NR_rt_sigpending == rax) return "__NR_rt_sigpending";
    else if (__NR_rt_sigtimedwait == rax) return "__NR_rt_sigtimedwait";
    else if (__NR_rt_sigqueueinfo == rax) return "__NR_rt_sigqueueinfo";
    else if (__NR_rt_sigreturn == rax) return "__NR_rt_sigreturn";
    else if (__NR_setpriority == rax) return "__NR_setpriority";
    else if (__NR_getpriority == rax) return "__NR_getpriority";
    else if (__NR_reboot == rax) return "__NR_reboot";
    else if (__NR_setregid == rax) return "__NR_setregid";
    else if (__NR_setgid == rax) return "__NR_setgid";
    else if (__NR_setreuid == rax) return "__NR_setreuid";
    else if (__NR_setuid == rax) return "__NR_setuid";
    else if (__NR_setresuid == rax) return "__NR_setresuid";
    else if (__NR_getresuid == rax) return "__NR_getresuid";
    else if (__NR_setresgid == rax) return "__NR_setresgid";
    else if (__NR_getresgid == rax) return "__NR_getresgid";
    else if (__NR_setfsuid == rax) return "__NR_setfsuid";
    else if (__NR_setfsgid == rax) return "__NR_setfsgid";
    else if (__NR_times == rax) return "__NR_times";
    else if (__NR_setpgid == rax) return "__NR_setpgid";
    else if (__NR_getpgid == rax) return "__NR_getpgid";
    else if (__NR_getsid == rax) return "__NR_getsid";
    else if (__NR_setsid == rax) return "__NR_setsid";
    else if (__NR_getgroups == rax) return "__NR_getgroups";
    else if (__NR_setgroups == rax) return "__NR_setgroups";
    else if (__NR_uname == rax) return "__NR_uname";
    else if (__NR_sethostname == rax) return "__NR_sethostname";
    else if (__NR_setdomainname == rax) return "__NR_setdomainname";
    else if (__NR_getrlimit == rax) return "__NR_getrlimit";
    else if (__NR_setrlimit == rax) return "__NR_setrlimit";
    else if (__NR_getrusage == rax) return "__NR_getrusage";
    else if (__NR_umask == rax) return "__NR_umask";
    else if (__NR_prctl == rax) return "__NR_prctl";
    else if (__NR_getcpu == rax) return "__NR_getcpu";
    else if (__NR_gettimeofday == rax) return "__NR_gettimeofday";
    else if (__NR_settimeofday == rax) return "__NR_settimeofday";
    else if (__NR_adjtimex == rax) return "__NR_adjtimex";
    else if (__NR_getpid == rax) return "__NR_getpid";
    else if (__NR_getppid == rax) return "__NR_getppid";
    else if (__NR_getuid == rax) return "__NR_getuid";
    else if (__NR_geteuid == rax) return "__NR_geteuid";
    else if (__NR_getgid == rax) return "__NR_getgid";
    else if (__NR_getegid == rax) return "__NR_getegid";
    else if (__NR_gettid == rax) return "__NR_gettid";
    else if (__NR_sysinfo == rax) return "__NR_sysinfo";
    else if (__NR_mq_open == rax) return "__NR_mq_open";
    else if (__NR_mq_unlink == rax) return "__NR_mq_unlink";
    else if (__NR_mq_timedsend == rax) return "__NR_mq_timedsend";
    else if (__NR_mq_timedreceive == rax) return "__NR_mq_timedreceive";
    else if (__NR_mq_notify == rax) return "__NR_mq_notify";
    else if (__NR_mq_getsetattr == rax) return "__NR_mq_getsetattr";
    else if (__NR_msgget == rax) return "__NR_msgget";
    else if (__NR_msgctl == rax) return "__NR_msgctl";
    else if (__NR_msgrcv == rax) return "__NR_msgrcv";
    else if (__NR_msgsnd == rax) return "__NR_msgsnd";
    else if (__NR_semget == rax) return "__NR_semget";
    else if (__NR_semctl == rax) return "__NR_semctl";
    else if (__NR_semtimedop == rax) return "__NR_semtimedop";
    else if (__NR_semop == rax) return "__NR_semop";
    else if (__NR_shmget == rax) return "__NR_shmget";
    else if (__NR_shmctl == rax) return "__NR_shmctl";
    else if (__NR_shmat == rax) return "__NR_shmat";
    else if (__NR_shmdt == rax) return "__NR_shmdt";
    else if (__NR_socket == rax) return "__NR_socket";
    else if (__NR_socketpair == rax) return "__NR_socketpair";
    else if (__NR_bind == rax) return "__NR_bind";
    else if (__NR_listen == rax) return "__NR_listen";
    else if (__NR_accept == rax) return "__NR_accept";
    else if (__NR_connect == rax) return "__NR_connect";
    else if (__NR_getsockname == rax) return "__NR_getsockname";
    else if (__NR_getpeername == rax) return "__NR_getpeername";
    else if (__NR_sendto == rax) return "__NR_sendto";
    else if (__NR_recvfrom == rax) return "__NR_recvfrom";
    else if (__NR_setsockopt == rax) return "__NR_setsockopt";
    else if (__NR_getsockopt == rax) return "__NR_getsockopt";
    else if (__NR_shutdown == rax) return "__NR_shutdown";
    else if (__NR_sendmsg == rax) return "__NR_sendmsg";
    else if (__NR_recvmsg == rax) return "__NR_recvmsg";
    else if (__NR_readahead == rax) return "__NR_readahead";
    else if (__NR_brk == rax) return "__NR_brk";
    else if (__NR_munmap == rax) return "__NR_munmap";
    else if (__NR_mremap == rax) return "__NR_mremap";
    else if (__NR_add_key == rax) return "__NR_add_key";
    else if (__NR_request_key == rax) return "__NR_request_key";
    else if (__NR_keyctl == rax) return "__NR_keyctl";
    else if (__NR_clone == rax) return "__NR_clone";
    else if (__NR_execve == rax) return "__NR_execve";
    else if (__NR3264_mmap == rax) return "__NR3264_mmap";
    else if (__NR3264_fadvise64 == rax) return "__NR3264_fadvise64";
#ifndef __ARCH_NOMMU
    else if (__NR_swapon == rax) return "__NR_swapon";
    else if (__NR_swapoff == rax) return "__NR_swapoff";
    else if (__NR_mprotect == rax) return "__NR_mprotect";
    else if (__NR_msync == rax) return "__NR_msync";
    else if (__NR_mlock == rax) return "__NR_mlock";
    else if (__NR_munlock == rax) return "__NR_munlock";
    else if (__NR_mlockall == rax) return "__NR_mlockall";
    else if (__NR_munlockall == rax) return "__NR_munlockall";
    else if (__NR_mincore == rax) return "__NR_mincore";
    else if (__NR_madvise == rax) return "__NR_madvise";
    else if (__NR_remap_file_pages == rax) return "__NR_remap_file_pages";
    else if (__NR_mbind == rax) return "__NR_mbind";
    else if (__NR_get_mempolicy == rax) return "__NR_get_mempolicy";
    else if (__NR_set_mempolicy == rax) return "__NR_set_mempolicy";
    else if (__NR_migrate_pages == rax) return "__NR_migrate_pages";
    else if (__NR_move_pages == rax) return "__NR_move_pages";
#endif
    else if (__NR_rt_tgsigqueueinfo == rax) return "__NR_rt_tgsigqueueinfo";
    else if (__NR_perf_event_open == rax) return "__NR_perf_event_open";
    else if (__NR_accept4 == rax) return "__NR_accept4";
    else if (__NR_recvmmsg == rax) return "__NR_recvmmsg";
    else if (__NR_arch_specific_syscall == rax) return "__NR_arch_specific_syscall";
    else if (__NR_wait4 == rax) return "__NR_wait4";
    else if (__NR_prlimit64 == rax) return "__NR_prlimit64";
    else if (__NR_fanotify_init == rax) return "__NR_fanotify_init";
    else if (__NR_fanotify_mark == rax) return "__NR_fanotify_mark";
    else if (__NR_name_to_handle_at == rax) return "__NR_name_to_handle_at";
    else if (__NR_open_by_handle_at == rax) return "__NR_open_by_handle_at";
    else if (__NR_clock_adjtime == rax) return "__NR_clock_adjtime";
    else if (__NR_syncfs == rax) return "__NR_syncfs";
    else if (__NR_setns == rax) return "__NR_setns";
    else if (__NR_sendmmsg == rax) return "__NR_sendmmsg";
    else if (__NR_process_vm_readv == rax) return "__NR_process_vm_readv";
    else if (__NR_process_vm_writev == rax) return "__NR_process_vm_writev";
    else if (__NR_kcmp == rax) return "__NR_kcmp";
    else if (__NR_finit_module == rax) return "__NR_finit_module";
    else if (__NR_sched_setattr == rax) return "__NR_sched_setattr";
    else if (__NR_sched_getattr == rax) return "__NR_sched_getattr";
    else if (__NR_renameat2 == rax) return "__NR_renameat2";
    else if (__NR_seccomp == rax) return "__NR_seccomp";
    else if (__NR_getrandom == rax) return "__NR_getrandom";
    else if (__NR_memfd_create == rax) return "__NR_memfd_create";
    else if (__NR_bpf == rax) return "__NR_bpf";
    else if (__NR_execveat == rax) return "__NR_execveat";
    else if (__NR_userfaultfd == rax) return "__NR_userfaultfd";
    else if (__NR_membarrier == rax) return "__NR_membarrier";
    else if (__NR_mlock2 == rax) return "__NR_mlock2";
    else if (__NR_copy_file_range == rax) return "__NR_copy_file_range";
    else if (__NR_preadv2 == rax) return "__NR_preadv2";
    else if (__NR_pwritev2 == rax) return "__NR_pwritev2";
    else if (__NR_pkey_mprotect == rax) return "__NR_pkey_mprotect";
    else if (__NR_pkey_alloc == rax) return "__NR_pkey_alloc";
    else if (__NR_pkey_free == rax) return "__NR_pkey_free";
    return "UNKNOW";
}