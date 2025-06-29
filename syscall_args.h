/**
 * @file syscall_args.h
 * @author Faisal Abdelmonem (fts@alumni.cmu.edu)
 * @brief 
 * @version 0.1
 * @date 2025-06-11
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef _SYSCALL_ARGS_H_
#define _SYSCALL_ARGS_H_

#define MAX_ARGS 6
#define MAX_SYSCALL_NR 512

typedef enum {
    ARG_UNKNOWN,
    ARG_INT,
    ARG_UINT,
    ARG_LONG,
    ARG_ULONG,
    ARG_SIZE_T,
    ARG_PID_T,
    ARG_STR,
    ARG_PTR,
    ARG_POLLFD_PTR
} arg_type_t;

typedef struct {
    int syscall_nr;
    // const char *name; We dont really need the symbol name do we?
    arg_type_t arg_types[MAX_ARGS];
} syscall_info_t;

// Define a syscall table
// extern const syscall_info_t syscall_table[];
// extern const int syscall_table_size;

const arg_type_t syscall_arg_table[MAX_SYSCALL_NR][MAX_ARGS] = {
    [0] = { ARG_UINT, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // read
    [1] = { ARG_UINT, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // write
    [2] = { ARG_STR, ARG_INT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // open
    [3] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // close
    [4] = { ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // stat
    [5] = { ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fstat
    [6] = { ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // lstat
    [7] = { ARG_POLLFD_PTR, ARG_UINT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // poll
    [8] = { ARG_UINT, ARG_LONG, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // lseek
    [9] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mmap
    [10] = { ARG_ULONG, ARG_SIZE_T, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mprotect
    [11] = { ARG_ULONG, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // munmap
    [12] = { ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // brk
    [13] = { ARG_INT, ARG_PTR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigaction
    [14] = { ARG_INT, ARG_PTR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigprocmask
    [15] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigreturn
    [16] = { ARG_UINT, ARG_UINT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ioctl
    [17] = { ARG_UINT, ARG_STR, ARG_SIZE_T, ARG_LONG, ARG_UNKNOWN, ARG_UNKNOWN }, // pread64
    [18] = { ARG_UINT, ARG_STR, ARG_SIZE_T, ARG_LONG, ARG_UNKNOWN, ARG_UNKNOWN }, // pwrite64
    [19] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // readv
    [20] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // writev
    [21] = { ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // access
    [22] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pipe
    [23] = { ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN }, // select
    [24] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_yield
    [25] = { ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // mremap
    [26] = { ARG_ULONG, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // msync
    [27] = { ARG_ULONG, ARG_SIZE_T, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mincore
    [28] = { ARG_ULONG, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // madvise
    [29] = { ARG_UNKNOWN, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // shmget
    [30] = { ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // shmat
    [31] = { ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // shmctl
    [32] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // dup
    [33] = { ARG_UINT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // dup2
    [34] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pause
    [35] = { ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // nanosleep
    [36] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getitimer
    [37] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // alarm
    [38] = { ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setitimer
    [39] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpid
    [40] = { ARG_INT, ARG_INT, ARG_LONG, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // sendfile
    [41] = { ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // socket
    [42] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // connect
    [43] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // accept
    [44] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_PTR, ARG_INT }, // sendto
    [45] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_PTR, ARG_INT }, // recvfrom
    [46] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sendmsg
    [47] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // recvmsg
    [48] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // shutdown
    [49] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // bind
    [50] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // listen
    [51] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getsockname
    [52] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpeername
    [53] = { ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // socketpair
    [54] = { ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN }, // setsockopt
    [55] = { ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN }, // getsockopt
    [56] = { ARG_ULONG, ARG_ULONG, ARG_INT, ARG_INT, ARG_ULONG, ARG_UNKNOWN }, // clone
    [57] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fork
    [58] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // vfork
    [59] = { ARG_STR, ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // execve
    [60] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // exit
    [61] = { ARG_PID_T, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // wait4
    [62] = { ARG_PID_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // kill
    [63] = { ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // uname
    [64] = { ARG_UNKNOWN, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // semget
    [65] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // semop
    [66] = { ARG_INT, ARG_INT, ARG_INT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN }, // semctl
    [67] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // shmdt
    [68] = { ARG_UNKNOWN, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // msgget
    [69] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // msgsnd
    [70] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_LONG, ARG_INT, ARG_UNKNOWN }, // msgrcv
    [71] = { ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // msgctl
    [72] = { ARG_UINT, ARG_UINT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fcntl
    [73] = { ARG_UINT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // flock
    [74] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fsync
    [75] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fdatasync
    [76] = { ARG_STR, ARG_LONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // truncate
    [77] = { ARG_UINT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ftruncate
    [78] = { ARG_UINT, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getdents
    [79] = { ARG_STR, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getcwd
    [80] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // chdir
    [81] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fchdir
    [82] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rename
    [83] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mkdir
    [84] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rmdir
    [85] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // creat
    [86] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // link
    [87] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // unlink
    [88] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // symlink
    [89] = { ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // readlink
    [90] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // chmod
    [91] = { ARG_UINT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fchmod
    [92] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // chown
    [93] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fchown
    [94] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // lchown
    [95] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // umask
    [96] = { ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // gettimeofday
    [97] = { ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getrlimit
    [98] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getrusage
    [99] = { ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sysinfo
    [100] = { ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // times
    [101] = { ARG_LONG, ARG_LONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN }, // ptrace
    [102] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getuid
    [103] = { ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // syslog
    [104] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getgid
    [105] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setuid
    [106] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setgid
    [107] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // geteuid
    [108] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getegid
    [109] = { ARG_PID_T, ARG_PID_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setpgid
    [110] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getppid
    [111] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpgrp
    [112] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setsid
    [113] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setreuid
    [114] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setregid
    [115] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getgroups
    [116] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setgroups
    [117] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setresuid
    [118] = { ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getresuid
    [119] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setresgid
    [120] = { ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getresgid
    [121] = { ARG_PID_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpgid
    [122] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setfsuid
    [123] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setfsgid
    [124] = { ARG_PID_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getsid
    [125] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // capget
    [126] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // capset
    [127] = { ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigpending
    [128] = { ARG_PTR, ARG_PTR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigtimedwait
    [129] = { ARG_PID_T, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigqueueinfo
    [130] = { ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_sigsuspend
    [131] = { ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sigaltstack
    [132] = { ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // utime
    [133] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mknod
    [134] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // uselib
    [135] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // personality
    [136] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ustat
    [137] = { ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // statfs
    [138] = { ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fstatfs
    [139] = { ARG_INT, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sysfs
    [140] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpriority
    [141] = { ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setpriority
    [142] = { ARG_PID_T, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_setparam
    [143] = { ARG_PID_T, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_getparam
    [144] = { ARG_PID_T, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_setscheduler
    [145] = { ARG_PID_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_getscheduler
    [146] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_get_priority_max
    [147] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_get_priority_min
    [148] = { ARG_PID_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_rr_get_interval
    [149] = { ARG_ULONG, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mlock
    [150] = { ARG_ULONG, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // munlock
    [151] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mlockall
    [152] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // munlockall
    [153] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // vhangup
    [154] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // modify_ldt
    [155] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pivot_root
    [156] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // _sysctl
    [157] = { ARG_INT, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // prctl
    [158] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // arch_prctl
    [159] = { ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // adjtimex
    [160] = { ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setrlimit
    [161] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // chroot
    [162] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sync
    [163] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // acct
    [164] = { ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // settimeofday
    [165] = { ARG_STR, ARG_STR, ARG_STR, ARG_ULONG, ARG_PTR, ARG_UNKNOWN }, // mount
    [166] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // umount2
    [167] = { ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // swapon
    [168] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // swapoff
    [169] = { ARG_INT, ARG_INT, ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // reboot
    [170] = { ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sethostname
    [171] = { ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setdomainname
    [172] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // iopl
    [173] = { ARG_ULONG, ARG_ULONG, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ioperm
    [174] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // create_module
    [175] = { ARG_PTR, ARG_ULONG, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // init_module
    [176] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // delete_module
    [177] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // get_kernel_syms
    [178] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // query_module
    [179] = { ARG_UINT, ARG_STR, ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // quotactl
    [180] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // nfsservctl
    [181] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getpmsg
    [182] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // putpmsg
    [183] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // afs_syscall
    [184] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // tuxcall
    [185] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // security
    [186] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // gettid
    [187] = { ARG_INT, ARG_LONG, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // readahead
    [188] = { ARG_STR, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN }, // setxattr
    [189] = { ARG_STR, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN }, // lsetxattr
    [190] = { ARG_INT, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN }, // fsetxattr
    [191] = { ARG_STR, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // getxattr
    [192] = { ARG_STR, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // lgetxattr
    [193] = { ARG_INT, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // fgetxattr
    [194] = { ARG_STR, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // listxattr
    [195] = { ARG_STR, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // llistxattr
    [196] = { ARG_INT, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // flistxattr
    [197] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // removexattr
    [198] = { ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // lremovexattr
    [199] = { ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fremovexattr
    [200] = { ARG_PID_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // tkill
    [201] = { ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // time
    [202] = { ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_PTR, ARG_PTR, ARG_UNKNOWN }, // futex
    [203] = { ARG_PID_T, ARG_UINT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_setaffinity
    [204] = { ARG_PID_T, ARG_UINT, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_getaffinity
    [205] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // set_thread_area
    [206] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // io_setup
    [207] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // io_destroy
    [208] = { ARG_UNKNOWN, ARG_LONG, ARG_LONG, ARG_PTR, ARG_PTR, ARG_UNKNOWN }, // io_getevents
    [209] = { ARG_UNKNOWN, ARG_LONG, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // io_submit
    [210] = { ARG_UNKNOWN, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // io_cancel
    [211] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // get_thread_area
    [212] = { ARG_UNKNOWN, ARG_STR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // lookup_dcookie
    [213] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_create
    [214] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_ctl_old
    [215] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_wait_old
    [216] = { ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // remap_file_pages
    [217] = { ARG_UINT, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getdents64
    [218] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // set_tid_address
    [219] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // restart_syscall
    [220] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // semtimedop
    [221] = { ARG_INT, ARG_LONG, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // fadvise64
    [222] = { ARG_UNKNOWN, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timer_create
    [223] = { ARG_UNKNOWN, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // timer_settime
    [224] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timer_gettime
    [225] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timer_getoverrun
    [226] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timer_delete
    [227] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // clock_settime
    [228] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // clock_gettime
    [229] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // clock_getres
    [230] = { ARG_UNKNOWN, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // clock_nanosleep
    [231] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // exit_group
    [232] = { ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_wait
    [233] = { ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_ctl
    [234] = { ARG_PID_T, ARG_PID_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // tgkill
    [235] = { ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // utimes
    [236] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // vserver
    [237] = { ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // mbind
    [238] = { ARG_INT, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // set_mempolicy
    [239] = { ARG_INT, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // get_mempolicy
    [240] = { ARG_STR, ARG_INT, ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // mq_open
    [241] = { ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mq_unlink
    [242] = { ARG_UNKNOWN, ARG_STR, ARG_SIZE_T, ARG_UINT, ARG_PTR, ARG_UNKNOWN }, // mq_timedsend
    [243] = { ARG_UNKNOWN, ARG_STR, ARG_SIZE_T, ARG_UINT, ARG_PTR, ARG_UNKNOWN }, // mq_timedreceive
    [244] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mq_notify
    [245] = { ARG_UNKNOWN, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mq_getsetattr
    [246] = { ARG_ULONG, ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN }, // kexec_load
    [247] = { ARG_INT, ARG_PID_T, ARG_PTR, ARG_INT, ARG_PTR, ARG_UNKNOWN }, // waitid
    [248] = { ARG_STR, ARG_STR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN }, // add_key
    [249] = { ARG_STR, ARG_STR, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // request_key
    [250] = { ARG_INT, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // keyctl
    [251] = { ARG_INT, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ioprio_set
    [252] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // ioprio_get
    [253] = { ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // inotify_init
    [254] = { ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // inotify_add_watch
    [255] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // inotify_rm_watch
    [256] = { ARG_PID_T, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN }, // migrate_pages
    [257] = { ARG_INT, ARG_STR, ARG_INT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN }, // openat
    [258] = { ARG_INT, ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mkdirat
    [259] = { ARG_INT, ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mknodat
    [260] = { ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_INT, ARG_UNKNOWN }, // fchownat
    [261] = { ARG_INT, ARG_STR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // futimesat
    [262] = { ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // newfstatat
    [263] = { ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // unlinkat
    [264] = { ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN }, // renameat
    [265] = { ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN }, // linkat
    [266] = { ARG_STR, ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // symlinkat
    [267] = { ARG_INT, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // readlinkat
    [268] = { ARG_INT, ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fchmodat
    [269] = { ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // faccessat
    [270] = { ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR }, // pselect6
    [271] = { ARG_POLLFD_PTR, ARG_UINT, ARG_PTR, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN }, // ppoll
    [272] = { ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // unshare
    [273] = { ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // set_robust_list
    [274] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // get_robust_list
    [275] = { ARG_INT, ARG_LONG, ARG_INT, ARG_LONG, ARG_SIZE_T, ARG_UINT }, // splice
    [276] = { ARG_INT, ARG_INT, ARG_SIZE_T, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN }, // tee
    [277] = { ARG_INT, ARG_LONG, ARG_LONG, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN }, // sync_file_range
    [278] = { ARG_INT, ARG_PTR, ARG_ULONG, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN }, // vmsplice
    [279] = { ARG_PID_T, ARG_ULONG, ARG_PTR, ARG_INT, ARG_INT, ARG_INT }, // move_pages
    [280] = { ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // utimensat
    [281] = { ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_SIZE_T }, // epoll_pwait
    [282] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // signalfd
    [283] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timerfd_create
    [284] = { ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // eventfd
    [285] = { ARG_INT, ARG_INT, ARG_LONG, ARG_LONG, ARG_UNKNOWN, ARG_UNKNOWN }, // fallocate
    [286] = { ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // timerfd_settime
    [287] = { ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // timerfd_gettime
    [288] = { ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // accept4
    [289] = { ARG_INT, ARG_PTR, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // signalfd4
    [290] = { ARG_UINT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // eventfd2
    [291] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // epoll_create1
    [292] = { ARG_UINT, ARG_UINT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // dup3
    [293] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pipe2
    [294] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // inotify_init1
    [295] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // preadv
    [296] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // pwritev
    [297] = { ARG_PID_T, ARG_PID_T, ARG_INT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // rt_tgsigqueueinfo
    [298] = { ARG_PTR, ARG_PID_T, ARG_INT, ARG_INT, ARG_ULONG, ARG_UNKNOWN }, // perf_event_open
    [299] = { ARG_INT, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN }, // recvmmsg
    [300] = { ARG_UINT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // fanotify_init
    [301] = { ARG_INT, ARG_UINT, ARG_UNKNOWN, ARG_INT, ARG_STR, ARG_UNKNOWN }, // fanotify_mark
    [302] = { ARG_PID_T, ARG_UINT, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN }, // prlimit64
    [303] = { ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, ARG_UNKNOWN }, // name_to_handle_at
    [304] = { ARG_INT, ARG_PTR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // open_by_handle_at
    [305] = { ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // clock_adjtime
    [306] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // syncfs
    [307] = { ARG_INT, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sendmmsg
    [308] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // setns
    [309] = { ARG_PTR, ARG_PTR, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getcpu
    [310] = { ARG_PID_T, ARG_PTR, ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG }, // process_vm_readv
    [311] = { ARG_PID_T, ARG_PTR, ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG }, // process_vm_writev
    [312] = { ARG_PID_T, ARG_PID_T, ARG_INT, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // kcmp
    [313] = { ARG_INT, ARG_STR, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // finit_module
    [314] = { ARG_PID_T, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_setattr
    [315] = { ARG_PID_T, ARG_PTR, ARG_UINT, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN }, // sched_getattr
    [316] = { ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_UINT, ARG_UNKNOWN }, // renameat2
    [317] = { ARG_UINT, ARG_UINT, ARG_PTR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // seccomp
    [318] = { ARG_STR, ARG_SIZE_T, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // getrandom
    [319] = { ARG_STR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // memfd_create
    [320] = { ARG_INT, ARG_INT, ARG_ULONG, ARG_STR, ARG_ULONG, ARG_UNKNOWN }, // kexec_file_load
    [321] = { ARG_INT, ARG_PTR, ARG_UINT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // bpf
    [322] = { ARG_INT, ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_UNKNOWN }, // execveat
    [323] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // userfaultfd
    [324] = { ARG_INT, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // membarrier
    [325] = { ARG_ULONG, ARG_SIZE_T, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // mlock2
    [326] = { ARG_INT, ARG_LONG, ARG_INT, ARG_LONG, ARG_SIZE_T, ARG_UINT }, // copy_file_range
    [327] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // preadv2
    [328] = { ARG_ULONG, ARG_PTR, ARG_ULONG, ARG_ULONG, ARG_ULONG, ARG_UNKNOWN }, // pwritev2
    [329] = { ARG_ULONG, ARG_SIZE_T, ARG_ULONG, ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN }, // pkey_mprotect
    [330] = { ARG_ULONG, ARG_ULONG, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pkey_alloc
    [331] = { ARG_INT, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN, ARG_UNKNOWN }, // pkey_free
    [332] = { ARG_INT, ARG_STR, ARG_UNKNOWN, ARG_UNKNOWN, ARG_PTR, ARG_UNKNOWN }, // statx
};

#endif // SYSCALL_ARGS_H