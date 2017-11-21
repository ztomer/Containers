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

/* << capabilities >> */
int capabilities(){

    fprintf(stderr, "=> dropping capabilities...");

    int drop_caps[] = {
        /* drop audit control (logs, etc) */
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ, /* Not namespaced */
        CAP_AUDIT_WRITE,

        CAP_BLOCK_SUSPEND, /* not namespaced, do not allow */
        CAP_DAC_READ_SEARCH, /* allows reading ionodes arbitrarily, disable */
        CAP_FSETID, /* disable setuid - which allows for privilege escalation */
        CAP_IPC_LOCK, /* allows locking process memory, can deny service - disable */

        CAP_MAC_ADMIN, /* used by Mandatory Access Control (selinux, etc) - disable*/
        CAP_MAC_OVERRIDE, /* */

        /* allows creating devices mapped to real-world devices.
        Can be used, for example, to unmount and mount an hdd, and then read/write
        from it.. - DISABLE */
        CAP_MKNOD, 

        CAP_SETFCAP, /* allows execve !! then can be run by unsandboxed user - diable */



        CAP_SYSLOG, /* allows changing the syslog - exposes kernel addresses - disable */
        CAP_SYS_ADMIN, /* disable tons of stuff (mount, vm86, sethostname, etc) */
        CAP_SYS_BOOT, /* allows reboot and loading new kernels - disable */
        CAP_SYS_MODULE, /* allows playing with kernel modules - disable */
        CAP_SYS_NICE, /* allows changing priority, can be used for DOS - disable */
        CAP_SYS_RAWIO, /* allows access to raw IO ports - disable */
        CAP_SYS_RESOURCE, /* allows DOSing the kernel - disable */
        CAP_SYS_TIME, /* allows changing systemwide time - disable */
        CAP_WAKE_ALARM /* Don't interefere with suspend */
    };

    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    fprintf(stderr, "bounding...");
    for (size_t i = 0; i < num_caps; i++){
        if (prctl(PR_CAPBSET_DROP, dorp_caps[i], 0, 0, 0)){
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc() )
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEANER)
        || cap_set_proc(caps)) {

        fprintf(stderr, "failed: %m \n");
        if (caps)
            cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done.\n");
    return 0;
}

/* << mounts >> */

/* PIVOT-ROOT 
* trying to unmount a directory without a permission by creating temp dir inside temp dir,
* mounting the internal temp dir to the target mount, and unmounting the parent dir
*/
int mounts(struct child_config *config){
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)){
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted\n");

    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)){
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }

    if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "bind mount failed!\n");
        return -1;
    }

    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir)){
        fprintf(stderr, "failed making the inner direcotry!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    fprintf(stderr, "=> pivoting root....");
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    char *old_root_dir = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir)+1] = {"/"};
    strcpy(&old_root[1], old_root_dir);

    fprintf(stderr, "=> unmounting %s...", old_root);
    if (chdir("/")){
        fprintf(stderr, "chdir failed! %m\n");
        return -1;
    }

    if (umount2(old_root, MNT_DETACH)){
        fprintf(stderr, "unmount failed! %m\n");
        return -1;
    }

    if (rmdir(old_root)){
        fprintf(stderr, "rmdir failed %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

/* PIVOT - ROOT */
/* swap old root mount wiht a new one */
int pivot_root(const char* new_root, const char* put_old){
    return syscall(SYS_pivot_root, new_root, put_old)
}

    

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
    int has_userns = !unshare(CLONE_NEWUSER);
    int io_size = 0;
    io_size = write(config->fd, &has_userns, sizeof(has_userns));
    if (io_size != sizeof(has_userns)){
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }

    io_size = 0;
    int result = 0;
    io_size = read(config->fd, &result, sizeof(result));
    if (io_size != sizeof(result)){
        fprintf(stderr, "couldn't read: %m\n");
        return -1;
    }

    if (result)
        return -1;

    if (has_userns){
        fprintf(stderr, "DONE.\n");
    } else {
        fprintf(stderr, "unsupported? continuing.\n");
    }

    fprintf(stderr, "=> switching to uid %d / gid %d..", config->uid, config->uid);

    if (setgroups(1, &(gid_t){ config->uid}) ||
        setgroups(config->uid, config->uid, config->uid) ||
        setgroups(config->uid, config->uid, config->uid)){
        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

/* Load executable with the new capabilities */
int child(void *arg){
    struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname)) 
        || mounts(config)
        || userns(config)
        || capabilities()
        || syscalls()
        ){
        close(config->fd);
        return -1;
    }
    if (close(config->fd)) {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }
    /* 
    Execute and replace current process with the configuration exec
    */
    if (execve(config->argv[0], config->argv, NULL)){
        fprintf(stderr, "execve failed %m.\n");
        return -1;
    }
    return 0;
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







