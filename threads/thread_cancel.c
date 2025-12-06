/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 32-1 */

/* thread_cancel.c

   Demonstrate the use of pthread_cancel() to cancel a POSIX thread.
*/

/*
 * VERBOSE COMMENTARY:
 * Cancellation is a request for a thread to stop.
 * Threads are not instantly killed (that would be unsafe). 
 * Instead, they terminate when they reach a "Cancellation Point".
 * Common cancellation points include system calls like sleep(), wait(), printf(), etc.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

static void *
threadFunc(void *arg)
{
    int j;

    printf("New thread started\n");     /* May be a cancellation point */
    for (j = 1; ; j++) {
        printf("Loop %d\n", j);         /* May be a cancellation point */
        
        /* * sleep() is a defined Cancellation Point.
         * If the main thread has called pthread_cancel(), this thread will stop
         * exactly here, inside the sleep call.
         */
        sleep(1);                       /* A cancellation point */
    }

    /* NOTREACHED - Code below is never executed because of cancellation */
    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;
    int s;
    void *res;

    s = pthread_create(&thr, NULL, threadFunc, NULL);
    if (s != 0)
        errExitEN(s, "pthread_create");

    sleep(3);                           /* Allow new thread to run a while */

    /*
     * Request cancellation of the target thread 'thr'.
     * By default, this is "Deferred Cancellation", meaning it waits for the 
     * target to hit a cancellation point.
     */
    s = pthread_cancel(thr);
    if (s != 0)
        errExitEN(s, "pthread_cancel");

    /*
     * Join the thread to clean up resources and get the exit status.
     * Even a canceled thread must be joined.
     */
    s = pthread_join(thr, &res);
    if (s != 0)
        errExitEN(s, "pthread_join");

    /*
     * Check if the thread was actually canceled.
     * PTHREAD_CANCELED is a special macro value ((void *) -1).
     */
    if (res == PTHREAD_CANCELED)
        printf("Thread was canceled\n");
    else
        printf("Thread was not canceled (should not happen!)\n");

    exit(EXIT_SUCCESS);
}

