/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter 30 */

/* prod_condvar.c

   A simple POSIX threads producer-consumer example using a condition variable.
*/

/*
 * VERBOSE COMMENTARY:
 * This solves the polling problem from prod_no_condvar.c.
 * It uses a Condition Variable ('cond').
 * * A Condition Variable allows a thread to "sleep" until another thread "signals" 
 * that a specific condition (like data being available) has become true.
 */

#include <time.h>
#include <pthread.h>
#include "tlpi_hdr.h"

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

/* Initialize the condition variable */
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static int avail = 0;

static void *
threadFunc(void *arg)
{
    int cnt = atoi((char *) arg);
    int s, j;

    for (j = 0; j < cnt; j++) {
        sleep(1);

        /* Code to produce a unit omitted */

        s = pthread_mutex_lock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        avail++;        /* Let consumer know another unit is available */

        s = pthread_mutex_unlock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");

        /*
         * SIGNAL THE CONSUMER
         * We have updated the state (avail > 0). Now we wake up the thread
         * that is sleeping on this condition variable.
         * If no one is waiting, the signal is lost (which is fine, the state is saved in 'avail').
         */
        s = pthread_cond_signal(&cond);         /* Wake sleeping consumer */
        if (s != 0)
            errExitEN(s, "pthread_cond_signal");
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t tid;
    int s, j;
    int totRequired;            /* Total number of units that all threads
                                   will produce */
    int numConsumed;            /* Total units so far consumed */
    Boolean done;
    time_t t;

    t = time(NULL);

    /* Create all threads */

    totRequired = 0;
    for (j = 1; j < argc; j++) {
        totRequired += atoi(argv[j]);

        s = pthread_create(&tid, NULL, threadFunc, argv[j]);
        if (s != 0)
            errExitEN(s, "pthread_create");
    }

    /* Loop to consume available units */

    numConsumed = 0;
    done = FALSE;

    for (;;) {
        s = pthread_mutex_lock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        /*
         * WAIT LOOP
         * We verify the condition (avail == 0).
         * While there is nothing to consume, we wait.
         * * IMPORTANT: This must be a 'while' loop, not an 'if'.
         * Why? "Spurious Wakeups". Sometimes threads wake up without a signal,
         * or another thread might consume the item before we get it. 
         * Always re-check the predicate after waking.
         */
        while (avail == 0) {            /* Wait for something to consume */
            
            /*
             * pthread_cond_wait
             * -----------------
             * 1. Atomically unlocks 'mtx'.
             * 2. Puts the thread to sleep (blocks).
             * 3. When signaled and woken: It automatically re-locks 'mtx' before returning.
             */
            s = pthread_cond_wait(&cond, &mtx);
            if (s != 0)
                errExitEN(s, "pthread_cond_wait");
        }

        /* At this point, 'mtx' is locked and we know avail > 0 */

        while (avail > 0) {             /* Consume all available units */

            /* Do something with produced unit */

            numConsumed ++;
            avail--;
            printf("T=%ld: numConsumed=%d\n", (long) (time(NULL) - t),
                    numConsumed);

            done = numConsumed >= totRequired;
        }

        s = pthread_mutex_unlock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");

        if (done)
            break;

        /* Perhaps do other work here that does not require mutex lock */

    }

    exit(EXIT_SUCCESS);
}


