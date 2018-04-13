#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <elf.h>

#ifndef ELFREADER_H
#define ELFREADER_H

	typedef struct ELF_INFO{
		char *filename;
		int fd;
		Elf64_Ehdr *hdr;
		Elf64_Shdr *shdr_table;
		Elf64_Sym *stc_sym_table;
		Elf64_Sym *dyn_sym_table;
		char *hdr_summary;
		char *shdr_names;
		char *stc_sym_names;
		char *dyn_sym_names;
		uint32_t stc_sym_size;
		uint32_t dyn_sym_size;
		unsigned char *seg_data;
	}elf_info;

	void *malloc_s(size_t s);
	char * elf_get_section_data(elf_info *ei_table, Elf64_Shdr *entry);
	unsigned char *elf_get_symbol_instructions(elf_info *ei_table, Elf64_Sym *symbol);
	int elf_print_symbols(elf_info *ei_table, uint32_t symtype);
	int elf_print_sections(elf_info *ei_table);
	Elf64_Shdr *elf_section_search(elf_info *ei_table, char *name, uint64_t addr);
	Elf64_Sym *elf_symbol_search(elf_info *ei_table, char *name, uint64_t addr);
	Elf64_Ehdr *elf_set_Ehdr(elf_info *ei_table);
	Elf64_Shdr *elf_set_Shdr_table(elf_info *ei_table);
	Elf64_Sym *elf_set_sym_table(elf_info *ei_table, uint32_t symtype);
	void elf_fini(elf_info *ei_table);
	elf_info *elf_init(char *filename);

#endif



