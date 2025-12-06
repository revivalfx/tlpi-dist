/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 32-2 */

/* thread_cleanup.c

   An example of thread cancellation using the POSIX threads API:
   demonstrate the use of pthread_cancel() and cleanup handlers.
*/

/*
 * VERBOSE COMMENTARY:
 * If a thread is canceled while it holds a mutex or has allocated memory,
 * that mutex might stay locked forever or the memory might leak.
 * * Cleanup Handlers act like a "stack" of functions to run upon cancellation.
 * You PUSH a handler when you allocate a resource.
 * You POP the handler when you release the resource naturally.
 * If canceled in between, the system pops and runs the handler for you.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static int glob = 0;                    /* Predicate variable */

static void     /* Free memory pointed to by 'arg' and unlock mutex */
cleanupHandler(void *arg)
{
    int s;

    /* The handler logic: Free the buffer and unlock the mutex */
    printf("cleanup: freeing block at %p\n", arg);
    free(arg);

    printf("cleanup: unlocking mutex\n");
    s = pthread_mutex_unlock(&mtx);
    if (s != 0)
        errExitEN(s, "pthread_mutex_unlock");
}

static void *
threadFunc(void *arg)
{
    int s;
    void *buf = NULL;                   /* Buffer allocated by thread */

    buf = malloc(0x10000);              /* Not a cancellation point */
    printf("thread:  allocated memory at %p\n", buf);

    s = pthread_mutex_lock(&mtx);       /* Not a cancellation point */
    if (s != 0)
        errExitEN(s, "pthread_mutex_lock");

    /*
     * PUSH CLEANUP HANDLER
     * We have acquired resources (malloc + mutex lock).
     * If we get canceled now, we need 'cleanupHandler' to run.
     * We pass 'buf' as the argument to the handler.
     */
    pthread_cleanup_push(cleanupHandler, buf);

    while (glob == 0) {
        /*
         * A CANCELLATION POINT
         * pthread_cond_wait is a cancellation point. 
         * If main cancels us while we wait here, the thread stops waiting,
         * and the cleanup handler stack is unwound (executing cleanupHandler).
         */
        s = pthread_cond_wait(&cond, &mtx);     /* A cancellation point */
        if (s != 0)
            errExitEN(s, "pthread_cond_wait");
    }

    printf("thread:  condition wait loop completed\n");
    
    /*
     * POP CLEANUP HANDLER
     * If we reach here naturally (no cancellation), we remove the handler.
     * The argument '1' means "Execute the handler now". 
     * This effectively does the cleanup (free + unlock) as part of normal execution.
     */
    pthread_cleanup_pop(1);             /* Executes cleanup handler */
    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;
    void *res;
    int s;

    s = pthread_create(&thr, NULL, threadFunc, NULL);
    if (s != 0)
        errExitEN(s, "pthread_create");

    sleep(2);                   /* Give thread a chance to get started */

    if (argc == 1) {            /* Cancel thread */
        printf("main:    about to cancel thread\n");
        /* Triggers the cleanup stack in the target thread */
        s = pthread_cancel(thr);
        if (s != 0)
            errExitEN(s, "pthread_cancel");

    } else {                    /* Signal condition variable */
        printf("main:    about to signal condition variable\n");

        /* Code to signal the thread naturally (normal termination path) */
        s = pthread_mutex_lock(&mtx);   /* See the TLPI page 679 erratum */
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        glob = 1;

        s = pthread_mutex_unlock(&mtx); /* See the TLPI page 679 erratum */
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");

        s = pthread_cond_signal(&cond);
        if (s != 0)
            errExitEN(s, "pthread_cond_signal");
    }

    s = pthread_join(thr, &res);
    if (s != 0)
        errExitEN(s, "pthread_join");
    if (res == PTHREAD_CANCELED)
        printf("main:    thread was canceled\n");
    else
        printf("main:    thread terminated normally\n");

    exit(EXIT_SUCCESS);
}

