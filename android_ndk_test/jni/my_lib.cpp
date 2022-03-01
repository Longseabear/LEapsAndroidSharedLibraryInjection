// code ref: https://teamcrak.tistory.com/378
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>

#define LIBC_PATH "/system/lib64/libc.so"
#define LOG_PATH "/data/local/tmp/openhook.log"

static int (*orig_open)(const char *f, ...) = NULL;

int open(const char* f, ...){
    int fd = 0, flags = 0, mode = 0;
    void *dl = NULL;
    va_list args;
    FILE *fp = fopen(LOG_PATH, "a+");
    
    if(fp==NULL) fp = stdout;

    fprintf(fp, "[HOOK-LIB] Executed open() system call: %s\n", f);
    if((dl=dlopen(LIBC_PATH, RTLD_LAZY)) == NULL){
        fprintf(fp, "[!] dlopen() function error.\n");
        return -1;
    }
    orig_open = (int(*)(const char* f, ...))dlsym(dl, "open");
    if(orig_open == NULL){
        fprintf(fp, "[HOOK-LIB] dlsym() function error\n");
        return -1;
    }
    va_start(args, f);
    flags = va_arg(args, int);
    mode = va_arg(args, int);
    va_end(args);
    if((fd = orig_open(f, flags, mode)) < 0){
        fprintf(fp, "[HOOK-LIB] origin function error: %s\n", f);
        return -1;
    }
    dlclose(dl);
    fclose(fp);
    return fd;
}