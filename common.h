/* oblique 2010
 */
#ifndef COMMON_H
#define COMMON_H

#include <unistd.h>
#include <sys/stat.h>

#define BUF_SIZE 32768


void print_error(char *file, unsigned int line, int errnum, char *s);
int copy_file_bytes(int dest, int src, off_t offset, size_t sz);
int replace_file(char *newfile, char *origfile, const struct stat origst);

#endif
