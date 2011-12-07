/*
 * win32 compile fix 05/01/2011 Dominik Meyer<meyerd@mytum.de>
 */

#include "n2n_win32.h"

int gettimeofday (struct timeval *tv, void* tz)
{
  union {
    long long ns100; /*time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  } now;

  GetSystemTimeAsFileTime (&now.ft);
  tv->tv_usec = (long) ((now.ns100 / 10LL) % 1000000LL);
  tv->tv_sec = (long) ((now.ns100 - 116444736000000000LL) / 10000000LL);
  return (0);
};

