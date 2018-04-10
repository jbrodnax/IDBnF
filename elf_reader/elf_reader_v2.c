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

char err_[] = "[!] Error ";
char err_set_Ehdr[]="(elf_set_Ehdr): ";
char err_init[]="(elf_init): ";

typedef struct ELF_INFO{
	char *filename;
	int fd;
	Elf64_Ehdr *hdr;
	char *hdr_summary;
	Elf64_Shdr *shdr_table;
	char *shdr_names;
	unsigned char *seg_data;
}elf_info;

elf_info *_ei_table;

void *malloc_s(size_t s){
	void *p;
	if((p = malloc(s)) == NULL){
		perror("[!] Error: malloc failed.");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, s);
	return p;
}

Elf64_Ehdr *elf_set_Ehdr(elf_info *ei_table){
	Elf64_Ehdr *hdr;
	uint32_t hdr_size;
	uint8_t MAGBUF[4] = {0x7f,0x45,0x4c,0x46};
	int fd;

	if(!ei_table)
		return NULL;

	fd = ei_table->fd;
	if(fd < 0){
		fprintf(stderr, "%s%sinvalid file descriptor.\n", err_, err_set_Ehdr);
		return NULL;
	}

	hdr_size = sizeof(Elf64_Ehdr);
	hdr = malloc_s(hdr_size);
	if((read(fd, hdr, hdr_size) < hdr_size)){
		fprintf(stderr, "%s%sfailed to read elf header.\n", err_, err_set_Ehdr);
		return NULL;
	}
	if((memcmp(MAGBUF, hdr->e_ident, 4)) != 0){
		fprintf(stderr, "%sIncorrect ELF magic number!\n", err_);
		return NULL;
	}
	if(hdr->e_version == 0)
		printf("[?] Warning: ELF version is not current.\n");

	ei_table->hdr = hdr;
	return hdr;
}

elf_info *elf_init(char *filename){
	elf_info *ei_table;
	int fd;

	if(!filename){
		fprintf(stderr, "%s%sreceived null argument.\n", err_, err_init);
		return NULL;
	}
	if((fd = open(filename, O_RDONLY)) < 0){
		fprintf(stderr, "%s%sfailed to open file: %s\n", err_, err_init, filename);
		return NULL;
	}

	ei_table = malloc_s(sizeof(elf_info));
	ei_table->filename = filename;
	ei_table->fd = fd;

	if(!elf_set_Ehdr(ei_table))
		return NULL;

	return ei_table;
}

int main(int argc, char **argv){

	_ei_table = elf_init(argv[1]);
	if(!_ei_table)
		return -1;

	puts("Success");
	free(_ei_table->hdr);
	free(_ei_table);
	return 0;
}




