#ifndef _UNISTD_H
#define _UNISTD_H
#include <stddef.h>
int access(const char *path, int mode);
#define F_OK 0
#define R_OK 4
#define W_OK 2
#define X_OK 1
#endif
