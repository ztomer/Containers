/* Local Variables: */
/* compile-command: "gcc -Wall -Werror -static subverting_networking.c \*/
/*                   -o subverting_networking.c */
/* End: */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>

int main(int argc, char**argv){
    /*
       unshare() allows a process (or thread) to disassociate parts of its
       execution context that are currently being shared with other
       processes (or threads).  Part of the execution context, such as the
       mount namespace, is shared implicitly when a new process is created
       using fork(2) or vfork(2), while other parts, such as virtual memory,
       may be shared by explicit request when creating a process or thread
       using clone(2).

       The main use of unshare() is to allow a process to control its shared
       execution context without creating a new process.
       */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET)){
        fprintf(stderr, "++ unshare failed: %m \n");
        return 1;
    }

    /* Now for bridge creation */
    int sock = 0;
    if ((sock = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1 ){
        fprintf(stderr, "++ socket failed: %m\n");
        return 1;
    } 

    if (ioctl(sock, SIOCBBRADDBR, "br0")) {
        fprintf(stderr, "++ ioctl failed: %m\n");
        close(sock);
        return 1;
    }
    close(sock);
    fprintf(stderr, "++ success!\n");
    return 0;
}