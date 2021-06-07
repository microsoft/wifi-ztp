
#ifndef __TIME_UTILS_H__
#define __TIME_UTILS_H__

#include <stdbool.h>
#include <time.h>

/**
 * @brief Timespec related helpers.
 */
#define MSEC_PER_SEC (1000L)
#define NSEC_PER_MSEC (1000000L)
#define NSEC_PER_USEC (1000L)
#define NSEC_PER_SEC (1000000000L)
#define USEC_PER_SEC (1000000L)

/**
 * @brief Helper to compare two struct timespec values. This is copied from
 * timercmp, changing the fields to work with timespec instead of timeval.
 */
#define timespeccmp(a, b, CMP)               \
    (((a)->tv_sec == (b)->tv_sec)            \
            ? ((a)->tv_nsec CMP(b)->tv_nsec) \
            : ((a)->tv_sec CMP(b)->tv_sec))

/**
 * @brief Calculates and returns the time difference of timespecs.
 * 
 * @param lhs Minuend.
 * @param rhs Subtrahend.
 * @return struct timespec difference.
 */
static inline struct timespec
timespec_diff(const struct timespec *lhs, const struct timespec *rhs)
{
    struct timespec diff;

    diff.tv_sec = lhs->tv_sec - rhs->tv_sec;
    diff.tv_nsec = lhs->tv_nsec - rhs->tv_nsec;

    if (diff.tv_nsec < 0) {
        diff.tv_sec--;
        diff.tv_nsec += NSEC_PER_SEC;
    }

    return diff;
}

/**
 * @brief Determines if a target time is earlier than a reference time.
 *
 * The time is assumed to be relative to some fixed epoch, and each of the
 * timespecs must have been obtained from the same clock source.
 *
 * The time is also assumed to respect contextual limits. Specifically, it is
 * expected that the 'tv_nsec' value does not exceed 1000000000 (the number of
 * nanoseconds in a second).
 *
 * @param target The time to check.
 * @param reference The time to compare against.
 * @return true If 'target' is earlier than 'reference'.
 * @return false If 'target' is later than or equal to 'reference'.
 */
bool
timespec_time_is_earlier(struct timespec *target, struct timespec *reference);

#endif //__TIME_UTILS_H__
