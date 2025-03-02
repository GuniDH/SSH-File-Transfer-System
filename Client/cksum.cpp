#include "cksum.h"


unsigned long memcrc(char* b, size_t n) {
	unsigned int v = 0, c = 0;
	unsigned long s = 0;
	unsigned int tabidx;

	for (int i = 0; i < n; i++) {
		tabidx = (s >> 24) ^ (unsigned char)b[i];
		s = UNSIGNED((s << 8)) ^ crctab[0][tabidx];
	}

	while (n) {
		c = n & 0377;
		n = n >> 8;
		s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
	}
	return (unsigned long)UNSIGNED(~s);

}