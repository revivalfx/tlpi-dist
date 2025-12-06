/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter Z */

/* seccomp_user_notification.c

   Demonstrate the seccomp notification-to-user-space feature added in
   Linux 5.0.

   This program creates two child processes, the "target" and the "tracer".

   The target process uses seccomp(2) to install a BPF filter using the
   SECCOMP_FILTER_FLAG_NEW_LISTENER flag. This flag causes seccomp(2) to return
   a file descriptor that can be used to receive notifications when the filter
   performs a return with the action SECCOMP_RET_USER_NOTIF; the BPF filter
   employed in this example performs such a return when the target process
   calls mkdir(2).

   The target process passes the notification file descriptor returned by
   seccomp(2) to the tracer process via a UNIX domain socket.

   The target process then performs a series of mkdir(2) calls using the
   pathnames supplied as command-line arguments to the program. The effect
   of each SECCOMP_RET_USER_NOTIF action triggered by these system calls is:

   (a) the mkdir(2) system call in the target process is *not* executed;
   (b) a notification is generated on the notification file descriptor;
   (c) the target process remains blocked in the mkdir(2) system call until
       a response is sent on the notification file descriptor (this response
       will include information for a "faked" return value for the mkdir(2)
       call--either a success return value, or a -1 error return with a value
       to be assigned to 'errno').

   The tracer process receives the notification file descriptor that was sent
   by the target process over the UNIX domain socket. It then waits for
   notifications using the SECCOMP_IOCTL_NOTIF_RECV ioctl(2) operation. Each
   of these notifications returns a structure that includes the PID of the
   target process, and information (the same 'struct seccomp_data' that a
   seccomp BPF filter receives) describing the target process's system call.
   In this example program, these notifications will relate to the mkdir(2)
   calls made by the target process.

   From user space, the tracer is able to do some things that an in-kernel
   seccomp BPF filter can't do; in particular, it can inspect the target
   process's memory (via /proc/PID/mem) in order to find out the values
   referred to by pointer arguments (e.g., the pathname argument of mkdir(2)).
   The tracer then makes a decision based on the pathname, creating the
   specified directory on behalf of the target process only if the pathname
   starts with ("/tmp/").

   The tracer then performs a SECCOMP_IOCTL_NOTIF_SEND ioctl(2) operation,
   which provides a response for the target process's system call. This
   response can specify either a success return value for the system call, or
   an error return, including a value that will be placed in 'errno' in the
   target process.
*/

/* seccomp_user_notification.c

   Detailed Explanation:
   This demonstrates SECCOMP_RET_USER_NOTIF.
   
   Architecture:
   1. Target Process: Installs a filter that says "If I call mkdir(), ask the user-space supervisor."
   2. Tracer Process: Receives the notification FD. Listens for events.
   3. When Target calls mkdir("/tmp/foo"), execution freezes.
   4. Tracer gets a notification. Tracer reads Target's memory to see the path string.
   5. Tracer decides to allow or deny.
   6. Tracer tells Kernel "Success" or "Error".
   7. Target unfreezes and receives the result as if the syscall finished.
*/

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "scm_functions.h" // Helper for sending FDs over sockets

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

/* Values from command-line options */

struct cmdLineOpts {
    int  delaySecs;     /* Delay logic to demonstrate blocking */
    int  secondFilter;  /* To demonstrate filter stacking/precedence */
    bool killTracer;    /* Cleanup logic */
};

/* The following is the x86-64-specific BPF boilerplate code for checking that
   the BPF program is running on the right architecture + ABI. At completion
   of these instructions, the accumulator contains the system call number. */

/* For the x32 ABI, all system call numbers have bit 30 set */

/* Boilerplate BPF macro to ensure we are running on x86-64 and not x32.
   Checks Arch == X86_64 and Syscall bit 30 is NOT set.
   Results in accumulator holding the syscall number.
*/
#define X32_SYSCALL_BIT         0x40000000

#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
                 (offsetof(struct seccomp_data, nr))), \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* Install the filter that requests User Notification for mkdir().
   Returns the Notification File Descriptor.
*/
/* installNotifyFilter() installs a seccomp filter that generates user-space
   notifications (SECCOMP_RET_USER_NOTIF) when the process calls mkdir(2); the
   filter allows all other system calls.

   The function return value is a file descriptor from which the user-space
   notifications can be fetched. */

static int
installNotifyFilter(void)
{
    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* Check: Is syscall mkdir? */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 0, 1),
        
        /* YES: Return SECCOMP_RET_USER_NOTIF. 
           This hands control to the listener holding the notify FD. */
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        /* NO: Allow everything else. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    int notifyFd;

    /* Crucial Flag: SECCOMP_FILTER_FLAG_NEW_LISTENER.
       This tells seccomp to create a new file descriptor that can be used 
       to listen for events generated by this filter.
    */
    notifyFd = seccomp(SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (notifyFd == -1)
        errExit("seccomp-install-notify-filter");

    return notifyFd;
}

/* Optional second filter to test return value precedence. 
   (e.g., if one filter says ERRNO and another says NOTIF, who wins?)
*/
static void
installFilter2(struct cmdLineOpts *opts)
{
    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* Treat mkdir() system calls specially */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mkdir, 1, 0),

        /* Every other system call is allowed */

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        { 0, 0, 0, 0 }, /* Placeholder for dynamic return value */
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
   /* Depending on the value of the "-f" command-line option, place either
       a SECCOMP_RET_ERRNO instruction in the BPF program, or otherwise a
       SECCOMP_RET_TRACE instruction. This can be used to illustrate that
       SECCOMP_RET_ERRNO has higher precedence than the SECCOMP_RET_USER_NOTIF
       returned by the other filter, with the result that the user-space
       notification will not occur. By contrast, SECCOMP_RET_TRACE has lower
       precedence (so that the user-space notification does occur). */
    /* Set the action based on CLI args (ERRNO vs TRACE) */
    const struct sock_filter retTrace = BPF_STMT(BPF_RET + BPF_K,
                                              SECCOMP_RET_TRACE);
    const struct sock_filter retErrno = BPF_STMT(BPF_RET + BPF_K,
                                              SECCOMP_RET_ERRNO | ENOTSUP);

    filter[prog.len - 1] = (opts->secondFilter == SECCOMP_RET_ERRNO) ?
                                        retErrno : retTrace;

    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog) == -1)
        errExit("seccomp-install-filter-2");
}

/* Handler for the SIGINT signal in the target process */

static void
handler(int sig)
{
    /* UNSAFE: This handler uses non-async-signal-safe functions
       (printf(); see TLPI Section 21.1.2) */

    printf("Target process: received signal\n");
}

/* Close a pair of sockets created by socketpair() */

static void
closeSocketPair(int sockPair[2])
{
    if (close(sockPair[0]) == -1)
        errExit("closeSocketPair-close-0");
    if (close(sockPair[1]) == -1)
        errExit("closeSocketPair-close-1");
}

/* Implementation of the target process; create a child process that:

   (1) installs a seccomp filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER
       flag;
   (2) writes the seccomp notification file descriptor returned from the
       previous step onto the UNIX domain socket, 'sockPair[0]';
   (3) calls mkdir(2) for each element of 'argv'.

   The function return value is the PID of the child process. */

/* Logic for the Target Process (the one being restricted).
*/
static pid_t
targetProcess(int sockPair[2], char *argv[], struct cmdLineOpts *opts)
{
    pid_t targetPid;
    int notifyFd;
    struct sigaction sa;
    int s;

    targetPid = fork();
    if (targetPid == -1)
        errExit("fork");

    if (targetPid > 0)          /* In parent, return PID of child */
        return targetPid;

    /* --- Child Process Code --- */

    printf("Target process: PID = %ld\n", (long) getpid());

    /* Setup signal handler (interrupt testing) */
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1)
        errExit("sigaction");

    /* Install seccomp filter(s) */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        errExit("prctl");

    /* Install filter and get the listener FD */
    notifyFd = installNotifyFilter();

    if (opts->secondFilter != -1)
        installFilter2(opts);

    /* IMPORTANT: The Target creates the filter/listener, but it can't 
       listen to itself easily (it's blocked!). It sends the listener FD 
       to the Tracer process via a UNIX socket.
    */
    if (sendfd(sockPair[0], notifyFd) == -1)
        errExit("sendfd");

    /* Target doesn't need the FD anymore */
    if (close(notifyFd) == -1)
        errExit("close-target-notify-fd");

    closeSocketPair(sockPair);

    /* Trigger the syscalls */
    for (char **ap = argv; *ap != NULL; ap++) {
        printf("\nTarget process: about to make directory \"%s\"\n", *ap);
        
        /* This call will BLOCK inside the kernel until the Tracer replies. */
        s = mkdir(*ap, 0600);
        
        if (s == -1)
            perror("Target process: mkdir");
        else
            printf("Target process: SUCCESS: mkdir(2) returned = %d\n", s);
    }

    printf("Target process: terminating\n");
    exit(EXIT_SUCCESS);
}

/* Helper to check if the notification ID is still valid.
   Prevents Time-of-Check-Time-of-Use (TOCTOU) races where the target dies
   and PID is recycled.
*/
static void
checkNotificationIdIsValid(int notifyFd, __u64 id, char *tag)
{
    if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == -1) {
        fprintf(stderr, "Tracer: notification ID check (%s): "
                "target has died!!!!!!!!!!!\n", tag);
    }
}

/* Logic for the Tracer Process (the supervisor).
*/
static void
watchForNotifications(int notifyFd, struct cmdLineOpts *opts)
{
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;
    char path[PATH_MAX];
    int procMem;        /* FD for /proc/PID/mem of target process */

    /* Get structure sizes from kernel (forward compatibility) */
    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == -1)
        errExit("Tracer: seccomp-SECCOMP_GET_NOTIF_SIZES");

    req = malloc(sizes.seccomp_notif);
    if (req == NULL)
        errExit("Tracer: malloc");

    resp = malloc(sizes.seccomp_notif_resp);
    if (req == NULL || resp == NULL)
        errExit("Tracer: malloc");

    /* Event Loop */
    for (;;) {
        /* Block and wait for a notification from the kernel */
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
            errExit("Tracer: ioctlSECCOMP_IOCTL_NOTIF_RECV");

        printf("Tracer: got notification for PID %d; ID is %llx\n",
                req->pid, req->id);

        /* If a delay interval was specified on the command line, then delay
           for the specified number of seconds. This can be used to demonstrate
           the following:

           (1) The target process is blocked until the tracer sends a response.
           (2) If the blocked system call is interrupted by a signal handler,
               then the SECCOMP_IOCTL_NOTIF_SEND operation fails with the error
               ENOENT.
           (3) If the target process terminates, then we can discover this
               using the SECCOMP_IOCTL_NOTIF_ID_VALID operation (which is
               employed by checkNotificationIdIsValid()). */

        if (opts->delaySecs > 0) {
            printf("Tracer: delaying for %d seconds:", opts->delaySecs);
            checkNotificationIdIsValid(notifyFd, req->id, "pre-delay");

            for (int d = opts->delaySecs; d > 0; d--) {
                printf(" %d", d);
                sleep(1);
            }
            printf("\n");

            checkNotificationIdIsValid(notifyFd, req->id, "post-delay");
        }

        /* INSPECTION:
           The notification contains registers (args), but mkdir takes a pointer (char*).
           The pointer points to memory inside the TARGET process, not the TRACER.
           We must open /proc/<pid>/mem to read the string from the Target's address space.
        */
        snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
        procMem = open(path, O_RDONLY);
        if (procMem == -1)
            errExit("Tracer: open");

        /* Verify Target is still the same process (hasn't died/respawned) */
        checkNotificationIdIsValid(notifyFd, req->id, "post-open");

        /* Since, the SECCOMP_IOCTL_NOTIF_ID_VALID operation (performed in
           checkNotificationIdIsValid()) succeeded, we know that the
           /proc/PID/mem file descriptor that we opened corresponded to the
           process for which we received a notification. If that process
           subsequently terminates, then read() on that file descriptor will
           return 0 (EOF). This can be tested by (1) uncommenting the sleep()
           call below (and rebuilding the program); (2) running the program
           with flags to ensure that the tracer is not killed if the target
           dies; and (3) killing the target process during the sleep(). */

        // printf("About to sleep in target\n");
        // sleep(15);

        /* Seek to the location containing the pathname argument (i.e., the
           first argument) of the mkdir(2) call and read that pathname */

        if (lseek(procMem, req->data.args[0], SEEK_SET) == -1)
            errExit("Tracer: lseek");

        /* Read the string */
        ssize_t s = read(procMem, path, sizeof(path));
        if (s == -1)
            errExit("read");
        else if (s == 0) {
            fprintf(stderr, "Tracer: read returned EOF\n");
            exit(EXIT_FAILURE);
        }

        printf("Tracer: mkdir(\"%s\", %llo)\n", path, req->data.args[1]);

        if (close(procMem) == -1)
            errExit("close-/proc/PID/mem");

        /* Prepare the response */
        resp->id = req->id;     // Must match the Request ID
        resp->flags = 0;        
        resp->val = strlen(path); // Faked return value (if success)

        /* POLICY DECISION:
           If path starts with "/tmp/", perform the mkdir on the target's behalf
           and tell the target "Success" (error=0).
           Otherwise, tell the target "Permission Denied" (error=-EPERM).
        */
        if (strncmp(path, "/tmp/", strlen("/tmp/")) == 0) {
            mkdir(path, req->data.args[1]); // Tracer does the work!
            resp->error = 0;
        } else {
            resp->error = -EPERM;
        }

        /* Provide a response to the target process */

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT)
                printf("Tracer: response failed with ENOENT; perhaps target "
                        "process's syscall was interrupted by signal?\n");
            else
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
        }

        /* If the pathname is just "/bye", then the tracer terminates. This
           allows us to see what happens if the target process makes further
           calls to mkdir(2). */

        if (strcmp(path, "/bye") == 0) {
            printf("Tracer: terminating <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
            exit(EXIT_FAILURE);
        }
    }
}

/* Implementation of the tracer process; create a child process that:

   (1) obtains the seccomp notification file descriptor from 'sockPair[1]';
   (2) handles notifications that arrive on that file descriptor.

   The function return value is the PID of the child process. */

static pid_t
tracerProcess(int sockPair[2], struct cmdLineOpts *opts)
{
    pid_t tracerPid;

    tracerPid = fork();
    if (tracerPid == -1)
        errExit("fork");

    if (tracerPid > 0)
        return tracerPid;

    /* Child falls through to here */

    printf("Tracer: PID = %ld\n", (long) getpid());

    /* Receive the notify FD from the Target via the socket */
    int notifyFd = recvfd(sockPair[1]);
    if (notifyFd == -1)
        errExit("recvfd");

    closeSocketPair(sockPair);

    watchForNotifications(notifyFd, opts);
    exit(EXIT_SUCCESS);
}

static void
usageError(char *msg, char *pname)
{
    if (msg != NULL)
        fprintf(stderr, "%s\n", msg);
    /* Usage print statements omitted for brevity, identical to source */

#define fpe(msg) fprintf(stderr, "      " msg);
    fprintf(stderr, "Usage: %s [options] <dir> <dir>...\n", pname);
    fpe("Options\n");
    fpe("-d <nsecs>    Tracer delays 'nsecs' before inspecting target\n");
    fpe("-f <val>      Install second filter whose return value is:\n");
    fpe("              'e' - SECCOMP_RET_ERRNO\n");
    fpe("              't' - SECCOMP_RET_TRACE\n");
    fpe("-K            Don't kill tracer on termination of target process\n");
    exit(EXIT_FAILURE);
}

/* Parse command-line options, returning option info in 'opts' */

static void
parseCommandLineOptions(int argc, char *argv[], struct cmdLineOpts *opts)
{
    /* Argument parsing logic (standard getopt) */
    int opt;
    opts->secondFilter = -1;
    opts->delaySecs = 0;
    opts->killTracer = true;

    while ((opt = getopt(argc, argv, "d:Kf:")) != -1) {
        switch (opt) {
        case 'K': opts->killTracer = false; break;
        case 'f':
            if (optarg[0] == 'e') opts->secondFilter = SECCOMP_RET_ERRNO;
            else if (optarg[0] == 't') opts->secondFilter = SECCOMP_RET_TRACE;
            else usageError("Bad value for -f", argv[0]);
            break;
        case 'd': opts->delaySecs = atoi(optarg); break;
        default: usageError("Bad option", argv[0]); exit(EXIT_FAILURE);
        }
    }
    if (optind >= argc)
        usageError("At least one pathname argument should be supplied", argv[0]);
}

int
main(int argc, char *argv[])
{
    pid_t targetPid, tracerPid;
    int sockPair[2];
    struct cmdLineOpts opts;

    setbuf(stdout, NULL);

    parseCommandLineOptions(argc, argv, &opts);

    /* Create a UNIX domain socket that is used to pass the seccomp
       notification file descriptor from the target process to the tracer
       process. */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1)
        errExit("socketpair");

    /* Create a child process--the "target"--that installs seccomp filtering.
       The target process writes the seccomp notification file descriptor
       onto 'sockPair[0]' and then calls mkdir(2) for each directory in the
       command-line arguments. */

    targetPid = targetProcess(sockPair, &argv[optind], &opts);

    /* Create the "tracer" as another child process. This allows the parent to
       wait on the target process and then either kill or wait on the tracer
       when the target terminates. The tracer reads the seccomp notification
       file descriptor from 'sockPair[1]' and then handles the notifications
       that arrive on that file descriptor. */

    tracerPid = tracerProcess(sockPair, &opts);

    /* The parent process does not need the socket pair */

    closeSocketPair(sockPair);

    /* Wait for Target to finish */
    waitpid(targetPid, NULL, 0);
    printf("Parent: target process has terminated\n");

    /* After the target process has terminated, either kill or wait for
       the tracer process */

    if (opts.killTracer) {
        printf("Parent: killing tracer\n");
        kill(tracerPid, SIGTERM);
    } else {
        waitpid(tracerPid, NULL, 0);
    }

    exit(EXIT_SUCCESS);
}


