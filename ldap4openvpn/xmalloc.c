#include <stdio.h>
#include <stdlib.h>
#include "xmalloc.h"

void *
xmalloc(size_t num)
{
	void *p = malloc(num);
	if (!p)
		fatal("Out of mem");
	return p;
}

void *
xrealloc(void *ptr,size_t num)
{
	void *p = realloc(ptr, num);
	if (!p) { /* realloc failed */
		free(ptr);
		ptr = NULL;
		num = 0;
 		fatal("Out of mem");
	}
	return p;
}

void 
fatal(const char *error)
{
	fprintf(stderr,"%s\n", error);
	exit(1);
} 	
