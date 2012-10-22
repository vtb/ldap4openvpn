#ifndef XMALLOC_H
#define XMALLOC_H

#ifdef MYMALLOC_DEBUG
extern int numOfAllocs;
#define XMALLOC(ptr, size) \
	numOfAllocs++;\
	ptr = xmalloc(size); 
#define XREALLOC(ptr, size) \
	if(ptr == NULL) \
		numOfAllocs++; \
	ptr = xrealloc(ptr,size); 
#define FREE(ptr) \
	numOfAllocs--;\
	free(ptr);
#else 
#define XMALLOC(ptr, size) \
	ptr = xmalloc(size);
#define XREALLOC(ptr, size) \
	ptr = xrealloc(ptr, size);
#define FREE(ptr) \
	free(ptr);
#endif 
	

void *xmalloc (size_t __num);
void *xrealloc (void *__ptr, size_t __num);
void fatal(const char *__error);
#endif /* XMALLOC_H */
