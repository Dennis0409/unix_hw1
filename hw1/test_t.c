
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "hw1_gpt.h"
#include "test.h"
// Define some constants
#define MAX_LOG_LEN 1024
#define MAX_PATH_LEN 1024
#define MAX_FD 1024
#define BLACKLIST_PATH "blacklist.txt"
#define MAX_IPS 1024
#define MAX_HOSTS 1024

// Define some global variables
static int (*real_open)(const char *pathname, int flags, mode_t mode) = NULL;
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*real_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) = NULL;
static int (*real_system)(const char *command) = NULL;
static int blacklist_fd[MAX_FD];
static int blacklist_fd_count = 0;
static char *blacklist_ips[MAX_IPS];
static int blacklist_ips_count = 0;
static char *blacklist_hosts[MAX_HOSTS];
static int blacklist_hosts_count = 0;
static char read_logs[MAX_FD][MAX_PATH_LEN];
static char write_logs[MAX_FD][MAX_PATH_LEN];

// Define the functions we use for logging and filtering
static void log_read(int fd, const char *buf, size_t count);
static void log_write(int fd, const char *buf, size_t count);
static int is_blacklisted_path(const char *path);
static int is_blacklisted_ip(const char *ip);
static int is_blacklisted_host(const char *host);

// Define the function that hijacks the entry point
void __libc_start_main(int (*main)(int, char**, char**), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void *__old_stack_size) {
    // Load the real __libc_start_main
    void (*real___libc_start_main)(int (*main)(int, char**, char**), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void *__old_stack_size);
    real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    // Load the real functions we need to hijack
    real_open = dlsym(RTLD_NEXT, "open");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    real_system = dlsym(RTLD_NEXT, "system");
    printf("pass ok\n");
    // Hijack the entry point and perform the necessary initializations
    //system("cat /proc/self/maps");
    printf("-----------test_t\n");
    //long open_addr;
    init_t("/bin/cat");

    //dlopen(libc.so.6) ---->  dlsym("_libc_start_main")
    //先call 真正的open 存起來 再蓋掉got table的位置 則使用時會呼叫到我的open 進行監控後再決定是否呼叫真正的open
    
    
    // Call the real __libc_start_main
    real___libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, __old_stack_size);
}
int main(){
    printf("ok\n");
    return 0;
}
// Define

