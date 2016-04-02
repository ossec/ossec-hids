#ifndef __SYSCHECK_ALLOW_H
#define __SYSCHECK_ALLOW_H

#include "shared.h"

int consumeAllowchange(const char *filename, Eventinfo *lf);
int produceAllowchange(time_t timestamp, const char *filename, Eventinfo *lf);
int DecodeAllowchange(Eventinfo *lf);

#endif
