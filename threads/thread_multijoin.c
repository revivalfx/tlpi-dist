/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 30-4 */

/* thread_multijoin.c

   This program creates one thread for each of its command-line arguments.
   Each thread sleeps for the number of seconds specified in the corresponding
   command-line argument, and then terminates. This sleep interval simulates
   "work" done by the thread.

   The program maintains a global array (pointed to by 'thread') recording
   information about all threads that have been created. The items of this
   array record the thread ID ('tid') and current state ('state', of type
   'enum tstate') of each thread.

   As each thread terminates, it sets its 'state' to TS_TERMINATED and
   signals the 'threadDied' condition variable. The main thread continuously
   waits on this condition variable, and is thus informed when any of the
   threads that it created has terminated. When 'numLive', which records
   the number of live threads, falls to 0, the main thread terminates.
*/

/*
 * VERBOSE COMMENTARY:
 * * The Problem: 
 * The standard 'pthread_join(tid, ...)' function waits for a *specific* thread 
 * ID. If you have 10 worker threads and you want to clean them up as soon as 
 * *any* of them finishes, standard pthreads API makes this difficult. If you 
 * join thread #1 but thread #2 finishes first, you remain blocked waiting for #1, 
 * leaving #2 as a "zombie" until #1 is done.
 *
 * The Solution:
 * This program implements a custom "Join Any" mechanism. It uses:
 * 1. A global array to track the state of every thread.
 * 2. A Mutex + Condition Variable pair. Threads signal the Condition Variable
 * when they are about to exit.
 * 3. The main thread waits on that Condition Variable, wakes up, scans the 
 * array to see who finished, and joins them immediately.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

/* * Synchronization Primitives:
 * threadDied: A condition variable used to wake up the main thread when a worker finishes.
 * threadMutex: A mutex to protect access to the global state variables (totThreads, 
 * numLive, numUnjoined, and the 'thread' array).
 */
static pthread_cond_t threadDied = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t threadMutex = PTHREAD_MUTEX_INITIALIZER;
                /* Protects all of the following global variables */

static int totThreads = 0;      /* Total number of threads created */
static int numLive = 0;         /* Total number of threads still alive or
                                   terminated but not yet joined */
static int numUnjoined = 0;     /* Number of terminated threads that
                                   have not yet been joined. This is the predicate
                                   for the condition variable wait. */

enum tstate {                   /* Thread states */
    TS_ALIVE,                   /* Thread is running */
    TS_TERMINATED,              /* Thread has finished execution but hasn't been joined yet */
    TS_JOINED                   /* Thread has finished and been joined (resources freed) */
};

/* Structure to maintain the status of every thread */
static struct {                 /* Info about each thread */
    pthread_t tid;              /* ID of this thread (returned by pthread_create) */
    enum tstate state;          /* Thread state (TS_* constants above) */
    int sleepTime;              /* Number seconds to live before terminating */
} *thread;

static void * /* Start function for thread */
threadFunc(void *arg)
{
    int idx = *((int *) arg);
    int s;

    /* Simulate "work" by sleeping for the specified duration */
    sleep(thread[idx].sleepTime);
    printf("Thread %d terminating\n", idx);

    /* * CRITICAL SECTION START
     * We are about to modify global state variables. We must lock the mutex.
     */
    s = pthread_mutex_lock(&threadMutex);
    if (s != 0)
        errExitEN(s, "pthread_mutex_lock");

    /* Mark ourselves as terminated so the main thread knows we are done */
    numUnjoined++;
    thread[idx].state = TS_TERMINATED;

    /* * CRITICAL SECTION END
     * Unlock the mutex before signaling. 
     */
    s = pthread_mutex_unlock(&threadMutex);
    if (s != 0)
        errExitEN(s, "pthread_mutex_unlock");
    
    /* * Signal the Condition Variable.
     * This sends a wake-up call to the main thread (which is sleeping on this CV).
     */
    s = pthread_cond_signal(&threadDied);
    if (s != 0)
        errExitEN(s, "pthread_cond_signal");

    return NULL;
}

int
main(int argc, char *argv[])
{
    int s, idx;

    if (argc < 2 || strcmp(argv[1], "--help") == 0)
        usageErr("%s num-secs...\n", argv[0]);

    /* Allocate the array of thread info structures based on command line args */
    thread = calloc(argc - 1, sizeof(*thread));
    if (thread == NULL)
        errExit("calloc");

    /* * Creation Loop:
     * Create all threads immediately. They will run concurrently.
     */
    for (idx = 0; idx < argc - 1; idx++) {
        thread[idx].sleepTime = getInt(argv[idx + 1], GN_NONNEG, NULL);
        thread[idx].state = TS_ALIVE;
        
        /* Note: We pass &idx as the argument, but be careful! In this loop, 'idx' changes.
           However, because we use 'idx' merely as an index during creation and the 
           thread reads from the global array, typically we'd want to pass a distinct 
           value. Here, since 'idx' is just an integer index used to access the global 
           array inside the thread, we cast the index to void*. (Wait, the code passes 
           (void*)&idx. This is actually risky if the loop proceeds before the thread 
           reads the arg, but in this specific code, the thread reads 'thread[idx]'? 
           Actually, the code casts arg back to int*. If the main loop increments idx 
           before the thread runs, the thread gets the wrong index.
           
           *Correction to standard practice*: Ideally, we should pass (void*)(long)idx 
           or a malloc'd int. The provided code passes &idx. This relies on the thread 
           starting and dereferencing 'arg' before the main loop continues, or implies 
           a potential race condition in argument passing. However, strictly adhering 
           to the instruction "Don't change code", we leave it as is.)
         */
        s = pthread_create(&thread[idx].tid, NULL, threadFunc, (void *) &idx);
        if (s != 0)
            errExitEN(s, "pthread_create");
    }

    totThreads = argc - 1;
    numLive = totThreads;

    /* * The Reaping Loop:
     * This loop continues as long as there are any threads left alive.
     */
    while (numLive > 0) {
        
        /* Lock mutex to check the condition predicate (numUnjoined) */
        s = pthread_mutex_lock(&threadMutex);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        /*
         * Wait for a thread to die.
         * We use a while loop to protect against "spurious wakeups" (waking up
         * without a signal).
         */
        while (numUnjoined == 0) {
            s = pthread_cond_wait(&threadDied, &threadMutex);
            if (s != 0)
                errExitEN(s, "pthread_cond_wait");
        }

        /* * At this point, we hold the lock and we know numUnjoined > 0.
         * We must find WHICH thread(s) terminated. 
         * Since the condition variable signal doesn't carry data (like a thread ID),
         * we scan our status array.
         */
        for (idx = 0; idx < totThreads; idx++) {
            if (thread[idx].state == TS_TERMINATED) {
                
                /* Found a terminated thread. Join it immediately. */
                s = pthread_join(thread[idx].tid, NULL);
                if (s != 0)
                    errExitEN(s, "pthread_join");

                /* Update state so we don't try to join it again */
                thread[idx].state = TS_JOINED;
                numLive--;
                numUnjoined--;

                printf("Reaped thread %d (numLive=%d)\n", idx, numLive);
            }
        }

        /* Unlock mutex after processing the state changes */
        s = pthread_mutex_unlock(&threadMutex);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");
    }

    exit(EXIT_SUCCESS);
}
