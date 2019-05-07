#ifndef __MEMZERO_H__
#define __MEMZERO_H__

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

void memzero(void *s, size_t n);

#if defined(__cplusplus)
}
#endif

#endif
