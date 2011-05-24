/* oblique 2010
 */
#ifndef INFECTOR_H
#define INFECTOR_H

#include <elf.h>

int check_elf32(Elf32_Ehdr *ehdr);
int check_elf64(Elf64_Ehdr *ehdr);

int infect_elf32(int fdi, int fdout);
int infect_elf64(int fd, int fdout);

void init_parasite32(unsigned char *code, Elf32_Addr jmp_vaddr, Elf32_Addr entry);
void init_parasite64(unsigned char *code, Elf64_Addr jmp_vaddr, Elf64_Addr entry);

#endif
