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

/* prod_no_condvar.c

   A simple POSIX threads producer-consumer example that doesn't use
   a condition variable.

   See also prod_condvar.c.
*/

/*
 * VERBOSE COMMENTARY:
 * This program has producer threads (creating units) and a main consumer thread.
 * * THE PROBLEM:
 * The consumer needs to wait for data. Without a condition variable, 
 * the consumer must continuously loop, locking the mutex, checking if 
 * 'avail > 0', and unlocking. 
 * * This is called "Polling" or "Busy Waiting". It burns CPU cycles unnecessarily 
 * checking a value that hasn't changed.
 */

#include <time.h>
#include <pthread.h>
#include "tlpi_hdr.h"

/* Mutex protects the shared variable 'avail' */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static int avail = 0; /* Number of units produced and ready for consumption */

static void *
threadFunc(void *arg)
{
    int cnt = atoi((char *) arg);
    int s, j;

    for (j = 0; j < cnt; j++) {
        sleep(1); /* Simulate time taken to produce an item */

        /* Code to produce a unit omitted */

        /* Acquire lock to update shared state */
        s = pthread_mutex_lock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        avail++;        /* Let consumer know another unit is available */

        s = pthread_mutex_unlock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t tid;
    int s, j;
    int totRequired;            /* Total number of units that all
                                   threads will produce */
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

    /* Use a polling loop to check for available units */

    numConsumed = 0;
    done = FALSE;

    /*
     * POLLING LOOP
     * The consumer runs this loop forever until done.
     */
    for (;;) {
        /* Lock mutex to safely check 'avail' */
        s = pthread_mutex_lock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        /* If there is data, consume it */
        while (avail > 0) {             /* Consume all available units */

            /* Do something with produced unit */

            numConsumed ++;
            avail--;
            printf("T=%ld: numConsumed=%d\n", (long) (time(NULL) - t),
                    numConsumed);

            done = numConsumed >= totRequired;
        }

        /* Unlock mutex */
        s = pthread_mutex_unlock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");

        if (done)
            break;

        /* Perhaps do other work here that does not require mutex lock */
        
        /* * CRITICAL NOTE:
         * If 'avail' was 0, we immediately loop back up and lock the mutex again.
         * This hammers the mutex and the CPU.
         */

    }

    exit(EXIT_SUCCESS);
}


