#ifndef _SYS_STAT_H
#define _SYS_STAT_H
#include <stddef.h>
struct stat { unsigned long st_size; int st_mode; };
int stat(const char *path, struct stat *buf);
int mkdir(const char *path, unsigned int mode);
#define S_ISDIR(m) (0)
#define S_ISREG(m) (1)
#endif
