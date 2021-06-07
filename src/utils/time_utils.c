
#include <assert.h>

#include "time_utils.h"

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
timespec_time_is_earlier(struct timespec *target, struct timespec *reference)
{
    assert((target->tv_nsec < NSEC_PER_SEC) && (reference->tv_nsec < NSEC_PER_SEC));

    return (target->tv_sec  < reference->tv_sec)
       || ((target->tv_sec == reference->tv_sec) && (target->tv_nsec < reference->tv_nsec));
}
