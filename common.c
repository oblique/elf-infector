/* oblique 2010
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "common.h"


void print_error(char *file, unsigned int line, int errnum, char *s) {
    fflush(stdout);
    if (file == NULL || line == 0)
        fprintf(stderr, "[-] %s: %s\n", s, strerror(errnum));
    else
        fprintf(stderr, "[-] %s:%d: %s: %s\n", file, line, s, strerror(errnum));
}

int replace_file(char *newfile, char *origfile, const struct stat origst) {
    struct timespec ts[2];

    if (rename(newfile, origfile) == -1)
        if (errno == EXDEV) {
            struct stat newst;
            int newfd, origfd;

            if (stat(newfile, &newst) == -1) {
                print_error(__FILE__, __LINE__-1, errno, "stat");
                return -1;
            }    

            if ((newfd = open(newfile, O_RDONLY)) == -1) {
                print_error(__FILE__, __LINE__-1, errno, "open");
                return -1;
            }

            if ((origfd = open(origfile, O_WRONLY | O_TRUNC)) == -1) {
                print_error(__FILE__, __LINE__-1, errno, "open");
                return -1;
            }

            if (copy_file_bytes(origfd, newfd, 0, newst.st_size) == -1)
                return -1;

            close(origfd);
            close(newfd);
            
            if (unlink(newfile) == -1)
                print_error(__FILE__, __LINE__-1, errno, "unlink");
        } else {
            print_error(__FILE__, __LINE__-1, errno, "rename");
            return -1;
        }


    if (chown(origfile, origst.st_uid, origst.st_gid) == -1)
        print_error(__FILE__, __LINE__-1, errno, "chown");

    if (chmod(origfile, origst.st_mode) == -1)
        print_error(__FILE__, __LINE__-1, errno, "chmod");

    ts[0] = origst.st_atim;
    ts[1] = origst.st_mtim;
    if (utimensat(AT_FDCWD, origfile, ts, 0) == -1)
        print_error(__FILE__, __LINE__-1, errno, "utimensat");

    return 0;
}

int copy_file_bytes(int dest, int src, off_t offset, size_t sz) {
    char buf[BUF_SIZE];
    int res, ret_sz;

    if (lseek(src, offset, SEEK_SET) == -1) {
        print_error(__FILE__, __LINE__-1, errno, "lseek");
        return -1;
    }

    if (sz % BUF_SIZE != 0) {
        if ((res = read(src, buf, sz % BUF_SIZE)) == -1) {
            print_error(__FILE__, __LINE__-1, errno, "read");
            return -1;
        } else if (res != sz % BUF_SIZE) {
            fprintf(stderr, "[-] File is too small\n");
            return -1;
        }

        if ((res = write(dest, buf, sz % BUF_SIZE)) == -1) {
            print_error(__FILE__, __LINE__-1, errno, "write");
            return -1;
        }

        sz -= sz % BUF_SIZE;
    }

    while (sz > 0) {
        if ((res = read(src, buf, BUF_SIZE)) == -1) {
            print_error(__FILE__, __LINE__-1, errno, "read");
            return -1;
        } else if (res != BUF_SIZE) {
            fprintf(stderr, "[-] File is too small\n");
            return -1;
        }

        if ((res = write(dest, buf, BUF_SIZE)) == -1) {
            print_error(__FILE__, __LINE__-1, errno, "write");
            return -1;
        }

        sz -= BUF_SIZE;
    }

    return 0;
}
