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
char err_set_Shdr_table[]="(elf_set_Shdr_table): ";
char err_set_sym_table[]="(elf_set_sym_table): ";
char err_get_section_data[]="(elf_get_section_data): ";
char err_print_symbols[]="(elf_print_symbols): ";

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
	unsigned char *seg_data;
}elf_info;

void *malloc_s(size_t s){
	void *p;
	if((p = malloc(s)) == NULL){
		perror("[!] Error: malloc failed.");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, s);
	return p;
}

char * elf_get_section_data(elf_info *ei_table, Elf64_Shdr *entry){
	char *section;
	int fd;

	if(!entry || !ei_table){
		fprintf(stderr, "%s%sinvalid argument.\n", err_, err_get_section_data);
		return NULL;
	}

	fd = ei_table->fd;
	if(fd < 0){
		fprintf(stderr, "%s%sfile descriptor has not been initialized.\n", err_, err_get_section_data);
		return NULL;
	}

	section = malloc_s(entry->sh_size);

	if((lseek(fd, (off_t)entry->sh_offset, SEEK_SET)) < 0){
		perror("lseek failed. ");
		exit(EXIT_FAILURE);
	}
	if((read(fd, section, entry->sh_size)) != entry->sh_size){
		perror("[!] Error (elf_get_section_data): read return value differs from entry.sh_size. ");
		exit(EXIT_FAILURE);
	}

	return section;
}

int elf_print_symbols(elf_info *ei_table, uint32_t symtype){
	Elf64_Shdr *shdr_table;
	Elf64_Sym *sym_table;
	uint32_t sym_count, j;
	uint16_t i;
	char *sym_names;

	if(!ei_table){
		fprintf(stderr, "%s%sreceived null ei_table.\n", err_, err_print_symbols);
		return -1;
	}
	shdr_table = ei_table->shdr_table;
	if(!shdr_table){
		fprintf(stderr, "%s%sei_table's shdr_table has not been initialized.\n", err_, err_print_symbols);
		return -1;
	}
	if(symtype == SHT_SYMTAB){
		sym_table = ei_table->stc_sym_table;
		sym_names = ei_table->stc_sym_names;
	}else if(symtype == SHT_DYNSYM){
		sym_table = ei_table->dyn_sym_table;
		sym_names = ei_table->dyn_sym_names;
	}else{
		fprintf(stderr, "%s%sinvalid symtype. symtype must be SHT_SYMTAB or SHT_DYNSYM.\n", err_, err_print_symbols);
		return -1;
	}

	if(!ei_table->hdr){
		fprintf(stderr, "%s%sei_table's hdr has not been initialized.\n", err_, err_print_symbols);
		return -1;
	}
	for(i=0;i<ei_table->hdr->e_shnum;i++){
		if(shdr_table[i].sh_type == symtype){
			sym_count = (shdr_table[i].sh_size/sizeof(Elf64_Sym));
			for(j=0;j<sym_count;j++){
				if(ELF64_ST_TYPE(sym_table[j].st_info) == STT_FUNC)
					printf("%-40s 0x%08x\n", (sym_names + sym_table[j].st_name), sym_table[j].st_value);
			}
		}
	}

	return 0;
}

Elf64_Ehdr *elf_set_Ehdr(elf_info *ei_table){
/*Fill new ei_table's elf header. Check elf magic number and version.*/
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

Elf64_Shdr *elf_set_Shdr_table(elf_info *ei_table){
	Elf64_Shdr *shdr_table;
	Elf64_Ehdr *hdr;
	Elf64_Off shoff;
	char *shdr_names;
	uint32_t shdr_size;
	uint16_t i;
	int fd;

	if(!ei_table){
		fprintf(stderr, "%s%sreceived null ei_table.\n", err_, err_set_Shdr_table);
		return NULL;
	}
	if(!ei_table->hdr){
		fprintf(stderr, "%s%sei_table has non-initialized elf header.\n", err_, err_set_Shdr_table);
		return NULL;
	}
	hdr = ei_table->hdr;

	fd = ei_table->fd;
	if(fd < 0){
		fprintf(stderr, "%s%sinvalid file descriptor.\n", err_, err_set_Shdr_table);
		return NULL;
	}

	shdr_size = (hdr->e_shentsize * hdr->e_shnum);
	shoff = hdr->e_shoff;
	if((shdr_size < 1) || (shoff < 1)){
		fprintf(stderr, "%s%sinvalid section parameter.\n", err_, err_set_Shdr_table);
		return NULL;
	}
	shdr_table = malloc_s(shdr_size);

	if((lseek(fd, (off_t)shoff, SEEK_SET)) < 0){
		perror("lseek failed. ");
		exit(EXIT_FAILURE);
        }

	for(i=0;i<hdr->e_shnum;i++){
		if((read(fd, &shdr_table[i], hdr->e_shentsize)) < hdr->e_shentsize){
			perror("read failed. ");
			exit(EXIT_FAILURE);
		}
	}

	if(!(shdr_names = elf_get_section_data(ei_table, &shdr_table[hdr->e_shstrndx])))
		return NULL;

	ei_table->shdr_names = shdr_names;
	ei_table->shdr_table = shdr_table;

	return shdr_table;
}

Elf64_Sym *elf_set_sym_table(elf_info *ei_table, uint32_t symtype){
	Elf64_Sym *sym_table;
	Elf64_Shdr *shdr_table;
	Elf64_Shdr shdr_entry;
	char *sym_names;
	uint32_t sym_count;
	uint16_t i;

	if(!ei_table){
		fprintf(stderr, "%s%sreceived null argument.\n", err_, err_set_sym_table);
		return NULL;
	}

	shdr_table = ei_table->shdr_table;
	if(!shdr_table){
		fprintf(stderr, "%s%sei_table's shdr_table has not been initialized.\n", err_, err_set_sym_table);
		return NULL;
	}

	for(i=0;i<ei_table->hdr->e_shnum;i++){
		if(shdr_table[i].sh_type == symtype)
			goto MATCH;
	}

	return NULL;

	MATCH:
		shdr_entry = shdr_table[i];
		sym_table = (Elf64_Sym *)elf_get_section_data(ei_table, &shdr_entry);
		sym_names = elf_get_section_data(ei_table, &shdr_table[shdr_entry.sh_link]);
		sym_count = (shdr_table[i].sh_size/sizeof(Elf64_Sym));

		/*for(j=0;j<sym_count;j++){
			if(ELF64_ST_TYPE(sym_table[j].st_info) == STT_FUNC)
				printf("%-40s 0x%08x\n", (sym_names + sym_table[j].st_name), sym_table[j].st_value);
		}*/
		if(symtype == SHT_SYMTAB){
			ei_table->stc_sym_table = sym_table;
			ei_table->stc_sym_names = sym_names;
		}else if(symtype == SHT_DYNSYM){
			ei_table->dyn_sym_table = sym_table;
			ei_table->dyn_sym_names = sym_names;
		}

		return sym_table;
}

void elf_fini(elf_info *ei_table){

	if(!ei_table)
		return;

	if(ei_table->hdr)
		free(ei_table->hdr);
	if(ei_table->shdr_table)
		free(ei_table->shdr_table);
	if(ei_table->stc_sym_table)
		free(ei_table->stc_sym_table);
	if(ei_table->dyn_sym_table)
		free(ei_table->dyn_sym_table);
	if(ei_table->hdr_summary)
		free(ei_table->hdr_summary);
	if(ei_table->shdr_names)
		free(ei_table->shdr_names);
	if(ei_table->stc_sym_names)
		free(ei_table->stc_sym_names);
	if(ei_table->dyn_sym_names)
		free(ei_table->dyn_sym_names);
	close(ei_table->fd);
	memset(ei_table, 0, sizeof(elf_info));

	return;
}

elf_info *elf_init(char *filename){
/*Initialize and allocate new ei_table.*/
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
	if(!elf_set_Shdr_table(ei_table))
		return NULL;
	if(!elf_set_sym_table(ei_table, SHT_SYMTAB))
		return NULL;
	if(!elf_set_sym_table(ei_table, SHT_DYNSYM))
		return NULL;

	return ei_table;
}

int main(int argc, char **argv){
	elf_info *ei_table;

	ei_table = elf_init(argv[1]);
	if(!ei_table)
		return -1;

	elf_print_symbols(ei_table, SHT_SYMTAB);
	elf_print_symbols(ei_table, SHT_DYNSYM);
	elf_fini(ei_table);

	return 0;
}




