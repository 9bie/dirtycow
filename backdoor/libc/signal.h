//
// Created by explorer on 2022/6/22.
//

#ifndef SCMAKER_SIGNAL_H
#define SCMAKER_SIGNAL_H

/*
 * Define our own sigset type instead of using glibc's sigset_t/__sigset_t.
 * Older glibc (e.g. CentOS 7) only provides __sigset_t via its internal
 * <bits/sigset.h>, while newer glibc uses <bits/types/sigset_t.h>; both
 * collide with definitions made here.  A private name avoids the clash.
 * Layout matches glibc: 1024 bits.
 */
typedef struct {
    unsigned long int __val[1024 / (8 * sizeof(unsigned long int))];
} scmaker_sigset_t;

#define SA_NOCLDSTOP  1
#define SA_NOCLDWAIT  2
#define SA_SIGINFO    4
#define SA_ONSTACK    0x08000000
#define SA_RESTART    0x10000000
#define SA_NODEFER    0x40000000
#define SA_RESETHAND  0x80000000
#define SA_RESTORER   0x04000000

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGILL    4
#define SIGTRAP   5
#define SIGABRT   6
#define SIGIOT    SIGABRT
#define SIGBUS    7
#define SIGFPE    8
#define SIGKILL   9
#define SIGUSR1   10
#define SIGSEGV   11
#define SIGUSR2   12
#define SIGPIPE   13
#define SIGALRM   14
#define SIGTERM   15
#define SIGSTKFLT 16
#define SIGCHLD   17
#define SIGCONT   18
#define SIGSTOP   19
#define SIGTSTP   20
#define SIGTTIN   21
#define SIGTTOU   22
#define SIGURG    23
#define SIGXCPU   24
#define SIGXFSZ   25
#define SIGVTALRM 26
#define SIGPROF   27
#define SIGWINCH  28
#define SIGIO     29
#define SIGPOLL   29
#define SIGPWR    30
#define SIGSYS    31
#define SIGUNUSED SIGSYS

#define _NSIG 65

#define SIG_ERR  ((void (*)(int))-1)
#define SIG_DFL  ((void (*)(int)) 0)
#define SIG_IGN  ((void (*)(int)) 1)

struct sigaction {
    void (*handler)(int);

    unsigned long flags;

    void (*restorer)(void);

    scmaker_sigset_t mask;
};

int sigemptyset(scmaker_sigset_t *);

int sigfillset(scmaker_sigset_t *);

int sigaddset(scmaker_sigset_t *, int);

int sigdelset(scmaker_sigset_t *, int);

int sigismember(const scmaker_sigset_t *, int);

typedef void (*sighandler_t)(int);

int sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict);

sighandler_t signal(int signum, sighandler_t handler);

#endif //SCMAKER_SIGNAL_H
