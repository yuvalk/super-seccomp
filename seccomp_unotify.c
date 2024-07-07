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
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

// Define SECCOMP_GET_NOTIF_FD if it's not already defined
#ifndef SECCOMP_GET_NOTIF_FD
#define SECCOMP_GET_NOTIF_FD 3
#endif

#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

// Function to handle the intercepted syscall
static int handle_syscall(struct seccomp_notif *req, struct seccomp_notif_resp *resp)
{
    struct seccomp_data *data = &req->data;
    
    // Handle write syscall
    if (data->nr == __NR_write) {
        int fd = data->args[0];
        uintptr_t buf_addr = data->args[1];
        size_t count = data->args[2];

        // Allocate buffer to read from child's memory
        char *buf = malloc(count);
        if (!buf) {
            perror("malloc");
            return -1;
        }

        // Read memory from child process
        struct iovec local_iov = {.iov_base = buf, .iov_len = count};
        struct iovec remote_iov = {.iov_base = (void *)buf_addr, .iov_len = count};
        if (process_vm_readv(req->pid, &local_iov, 1, &remote_iov, 1, 0) == -1) {
            perror("process_vm_readv");
            free(buf);
            return -1;
        }

        // Perform the write syscall
        ssize_t ret = write(fd, buf, count);

        // Set the response
        resp->id = req->id;
        resp->error = (ret < 0) ? -errno : 0;
        resp->val = (ret >= 0) ? ret : 0;

        free(buf);
        return 0;
    }

    // Unsupported syscall
    resp->id = req->id;
    resp->error = -ENOSYS;
    resp->val = 0;
    return 0;
}

int main(void)
{
    int notif_fd, child_pid;

    // Fork a child process
    child_pid = fork();

    if (child_pid == 0) {
        // Child process
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
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

        // Handle notifications
        struct seccomp_notif *req;
        struct seccomp_notif_resp *resp;
        struct seccomp_notif_sizes sizes;

        if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1) {
            perror("seccomp");
            exit(1);
        }

        req = malloc(sizes.seccomp_notif);
        resp = malloc(sizes.seccomp_notif_resp);

        while (1) {
            memset(req, 0, sizes.seccomp_notif);
            if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
                if (errno == EINTR)
                    continue;
                perror("ioctl");
                break;
            }

            if (handle_syscall(req, resp) == -1) {
                fprintf(stderr, "Failed to handle syscall\n");
                break;
            }

            if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
                perror("ioctl");
                break;
            }
        }

        free(req);
        free(resp);
        close(notif_fd);

        wait(NULL);
    } else {
        perror("fork");
        exit(1);
    }

    return 0;
}
