#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdarg.h>

// Shared Event Numbers with VMI monitor
#define PUTS_EVENT 2
#define OPEN_EVENT 3
#define CLOSE_EVENT 4
#define FORK_EVENT 5
#define EXEC_EVENT 6

// Hooked Functions Definitions
typedef int (*libc_puts)(const char *);

typedef int (*libc_open)(const char *, int, ...);
typedef int (*libc_close)(int);
typedef FILE * (*libc_fopen)( const char *, const char *);
typedef int (*libc_fclose)(FILE *);

typedef pid_t (*libc_fork)(void);

static void* libc_handle;
void* mypage_buffer = (void *)1;
static char signature_buffer[56];

void __attribute__((constructor)) patch_startup()
{
	printf("Patch Library startup\n");
	// Retrieve libc handle
	libc_handle = dlopen("libc.so.6", RTLD_LAZY);
	// Create memory page
	long page_size = sysconf(_SC_PAGESIZE);
	mypage_buffer = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	if (mypage_buffer == MAP_FAILED)
	{
		printf("Memory page could not be created");
		return;
	}

	mlock(mypage_buffer, page_size);

	// Create signature for VMI monitor
	snprintf(signature_buffer, 56, "<15b53bb4-cbf1-4a72-8faf-bb8ae152f23d>%p", mypage_buffer);
	printf("Page Signature: %s\n", signature_buffer);
}

void __attribute__((destructor)) patch_shutdown()
{
	printf("Patch Library shutdown\n");

	// Close libc handle
	dlclose(libc_handle);
}

FILE * patch_fopen(const char * filename, const char * mode)
{
        // Write to memory page
        *((int*)mypage_buffer)= OPEN_EVENT;

        printf("fopen - Function called! Page Value : %d\n", *((int*)mypage_buffer));

        if(!libc_handle) {
                printf("fopen - dlopen() failed.\n");
                libc_fopen func = (libc_fopen)dlsym(RTLD_NEXT,"fopen");
                return func(filename, mode);
        }

        libc_fopen func = (libc_fopen)dlsym(libc_handle,"fopen");
        if (!func){
                printf("fopen - dlsym() failed.\n");
                return NULL;
        }

        return func(filename, mode);
}

int patch_fclose(FILE * stream)
{
        // Write to memory page
        *((int*)mypage_buffer)= CLOSE_EVENT;

        printf("fclose - Function called! Page Value : %d\n", *((int*)mypage_buffer));
        if(!libc_handle) {
                printf("fclose - dlopen() failed.\n");
                libc_fclose func = (libc_fclose)dlsym(RTLD_NEXT,"fclose");
                return func(stream);
        }

        libc_fclose func = (libc_fclose)dlsym(libc_handle,"fclose");
        if (!func){
                printf("fclose - dlsym() failed.\n");
                return -1;
        }

        return func(stream);
}

int patch_open(const char *pathname, int flags, ...)
{
	// Write to memory page
	*((int*)mypage_buffer)= OPEN_EVENT;

	printf("open - Function called! Page Value : %d\n", *((int*)mypage_buffer));

	va_list ap;
	mode_t mode;

	va_start(ap, flags);
	mode = va_arg(ap, mode_t);
	va_end(ap);

	if(!libc_handle) {
   		printf("open - dlopen() failed.\n");
		libc_open func = (libc_open)dlsym(RTLD_NEXT,"open");
		return func(pathname, flags, mode);
	}

	libc_open func = (libc_open)dlsym(libc_handle,"open");
	if (!func){
		printf("open - dlsym() failed.\n");
		return -1;
	}

	return func(pathname, flags, mode);
}

int patch_close(int fildes)
{
	// Write to memory page
	*((int*)mypage_buffer)= CLOSE_EVENT;

	printf("close - Function called! Page Value : %d\n", *((int*)mypage_buffer));
	if(!libc_handle) {
   		printf("close - dlopen() failed.\n");
		libc_close func = (libc_close)dlsym(RTLD_NEXT,"close");
		return func(fildes);
	}

	libc_close func = (libc_close)dlsym(libc_handle,"close");
	if (!func){
		printf("close - dlsym() failed.\n");
		return -1;
	}

	return func(fildes);
}

pid_t patch_fork()
{
        // Write to memory page
        *((int*)mypage_buffer)= FORK_EVENT;

        printf("fork - Function called! Page Value : %d\n", *((int*)mypage_buffer));
        if(!libc_handle) {
                printf("fork - dlopen() failed.\n");
                libc_fork func = (libc_fork)dlsym(RTLD_NEXT,"fork");
                return func();
        }

        libc_fork func = (libc_fork)dlsym(libc_handle,"fork");
        if (!func){
                printf("fork - dlsym() failed.\n");
                return -1;
        }

        return func();
}

int patch_puts(const char * str)
{
	// Write to memory page
	*((int*)mypage_buffer)= PUTS_EVENT;

	printf("puts - Function called! Page Value : %d\n", *((int*)mypage_buffer));
	if(!libc_handle) {
   		printf("puts - dlopen() failed.\n");
		libc_puts func = (libc_puts)dlsym(RTLD_NEXT,"puts");
		return func(str);
	}

	libc_puts func = (libc_puts)dlsym(libc_handle,"puts");
	if (!func){
		printf("puts - dlsym() failed.\n");
		return -1;
	}

	return func(str);
}

