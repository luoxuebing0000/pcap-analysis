#include "mymemory.h"
#include <string.h>
#include <stdlib.h>	
#include <stdio.h>

void* zero_alloc(size_t size)
{
	if (size <= 0)
		return NULL;

	void* mem = malloc(size);
	if (mem == NULL) {
		printf("malloc memory error\n");
		exit(-1);
	}

	memset(mem, 0, size);

	return mem;
}