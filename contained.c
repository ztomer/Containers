/* https://blog.lizzie.io/linux-containers-in-500-loc.html#sec-2-3 */

/* namespaces - groups kernel objects into sets that can be accesses by a specific 
process tree */

/* capabilities - coarse limits on hwat uid 0 can do */
/* cgroups - limit resource usage - mem, diskio, cputime  - accessed using sysfs */
/* setrlimit - older resource limit usage - accessed using syscalls*/

/* -*- compile-command: "gcc -Wall -Werror -lcap -lseccomp contained.c -o contained" -*- */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>

strut child_config {
    int argc;
    uid_t uid;
    int fd;
    char *hostname;
    char **argv;
    char *mount_dir;
};

/* << capabilities >> /*
/* << mounts >> */
/* << syscalls >> */
/* << resources >> */


/* << child >> */
/*
Child processes
*/
#define USERNS_OFFSET (10000)
#define USERNS_COUNT (2000)

int handle_child_uid_map(pid_t child_pid, int fd){
    int uid_map = 0;
    int has_userns = -1;

    /* Read from file descriptor*/
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)){
        fprintf(stderr, "couldn't read from child!\n");
        return -1;
    }

    if (has_userns){
        char path[PATH_MAX] = {0};


        /* creates an array with 3 elements end iterates over them 
        * First load the UID map, and then load the GID map, stop when reaching the last element (0)
        * (That's a semi clever way to avoid using an index variable, but instead dereferce memory.)
        */
        for (char **file = (char*[]) {"uid_map", "gid_map", 0}; *file; file++) {
            if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file) > sizeof(path)){
                fprintf(stderr, "snprintf too big? %m\n");
                return -1;
            }
            fprintf(stderr, "writing %s...", path);
            if ((uid_map = open(path, O_WRONLY)) == -1) {
                fprintf(stderr, "open failed: %m\n");
                return -1;
            }
            /* print to file descriptor */
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1){
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return -1;
            }
            close(uid_map);
        }
    }
    /* Close the file descriptio by writign a NULL*/
    if (write(fd, &(int){0}, sizeof(int)) != sizeof(int)){
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }
    return 0;
}

int userns(struct child_config* config){
    fprintf(stderr, "=> trying a user namespace...");
    int has_userns
}


/*****************************************************************************/


/* << choose-hostname >> */
/* Hostname is a tarot card name */
int choose_hostname(char *buff, size_t len){
    static const char* suits[] = {"swords", "wands", "pentacles", "cups"};
    static const char* minor[] = {"ace", "two", "three", "four", "five", "six", "seven",
        "eight", "nine", "ten", "page", "knight", "queen", "king"};
    static const char* major[]= {"fool", "magician", "high-priestess", "empress", "emperor", 
        "hierophant", "lovers", "chariot", "strength", "hermit", "wheel", "justice", "hanged-man", 
        "death", "temperance", "devil", "tower", "star", "moon", "sun", "judgment", "world"};

    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    int num_major = sizeof(major) / sizeof(*major); /* 22 */
    int num_minor = sizeof(minor) / sizeof(*minor); /* 14 */
    size_t ix = now.tv_nsec % 78;
    if (ix < num_major){
        snprintf(buff, len, "0x5lx-%s", now.tv_sec, major[ix]);
    } else {
        ix -= num_major;
        snprintf(buff, len, "%05lxc-%s-of-%s", now.tv_sec, minor[ix % num_minor], suits[ix / num_minor];
    }

    return 0;
}




int main (int argc, char** argv){
    struct child_config config = {0};
    int err = 0;
    int option = 0;
    int sockets[2] = {0};
    pid_t child_pid = 0;
    int last_optind = 0;

    while ((options = getopt(argc, argv, "c:m:u"))) {
        switch(option) {
            case 'c':
                config.argc = argc - last_optind - 1;
                config.argv = &argv[argc - config.argc];
                goto finish_options;
            case 'm':
                config.mount_dir = optarg;
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1) {
                    fprintf(stderr, "badly formatted uid: %s\n", optarg);
                    goto usage;
                }
                break;
            default:
                goto usage;
        }
        last_optind = optind;
    }

    finish_options:
        if (!config.argc) goto usage;
        if (!config.mount_dir) goto usage;

    /* 
    <<check-linux-version>> 
    */
    /* blacklisting syscalls and capabilities, checking for valid versions */    
    fprintf(stderr, "=> validating Linux version..");
    struct utsname host = {0};
    if (uname(&host)){
        fprintf(stderr, "failed: %m\n");
        goto cleanup;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u", &major, &minor) !=2){
        fprintf(stderr, "weird release format: %s\n", host.release);
        goto cleanup;
    }
    if (major != 4 || (minor != 7 && minotr != 8)){
        fprintf(stderr, "expected 4.7.x or 4.8.x: %s\n", host.release);
        goto cleanup;
    }
    if (strcmp("x86_64", host.machine)) {
        fprintf(stderr, "expected x86_64: %s\n", host.machine);
        goto cleanup;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine );

    /* -------------------------- */    

    /* Check Hostname */
    char hostname[256] = {0};
    if (choose_hostname(hostname, sizeof(hostname)))
        goto error;
    config.hostname = hostname;

    /* <<namespaces>> */
    /* 
    we want create a process with different properties than the parent.
    Before we do it, we need a way to communicate with the parent process
    -- communication is done over a socketpair
    */
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)){
        fprintf(stderr, "socketpair failed: %m\n");
        goto error;
    }
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)){
        fprintf(stderr, "fcntl failed: %m \n")
        goto error;
    }
    config.fd = sockets[1];

    /* alloacte stack */
    #define STACK_SIZE (1024*1024)

    char* stack = malloc(STACK_SIZE);
    if (!stack) {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        goto error;
    }

    /* Prepare cgroup for hte process tree */
    if (resources(&config)){
        err = 1;
        goto clear_resources;
    }
    int flags = CLONE NEWNS 
        | CLONE_NEWCGROUP
        | CLONE_NEWPID
        | CLONE_NEWIPC
        | CLONE_NEWNET
        | CLONE_NEWUTS;

    /*
    Clone the process.
    stack grows downwar. get the end of the stack */
    int child_pid = clone(child, stack + STACK_SIZE, flags, | SIGCHLD, &config);
    if (child_pid == -1 ) {
        fprintf(stderr, "=> clone failed! %m\n");
        err = 1;
        goto clear_resources;
    }


    close(sockets[1]);
    sockets[1] = 0;



    /* ---------------------------- */
    goto cleanup;

usage:
    fprintf(stderr, "Usage: %s -u -1 -m . -c /bin/sh ~\n", argv[0]);
error:
    err = 1;
cleanup:
    if (sockets[0])
        close(sockets[0]);
    if (sockets[1])
        close(sockets[1]);
    return err;
}






