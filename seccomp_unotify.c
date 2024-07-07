#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>

#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

int main(int argc, char *argv[])
{
    int notif_fd, child_pid;

    // Fork a child process
    child_pid = fork();

    if (child_pid == 0) {
        // Child process
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };

        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };

        if (seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog) == -1) {
            perror("seccomp");
            exit(1);
        }

        // Perform a write syscall
        write(STDOUT_FILENO, "Hello, World!\n", 14);

        exit(0);
    } else if (child_pid > 0) {
        // Parent process
        notif_fd = seccomp(SECCOMP_GET_NOTIF_FD, 0, NULL);
        if (notif_fd == -1) {
            perror("seccomp");
            exit(1);
        }

        // Handle notifications here
        // TODO: Implement notification handling

        wait(NULL);
    } else {
        perror("fork");
        exit(1);
    }

    return 0;
}
