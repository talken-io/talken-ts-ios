#include <string.h>

void memzero(void *s, size_t n)
{
	memset(s, 0xff, n);
	memset(s, 0x55, n);
	memset(s, 0x00, n);
}
