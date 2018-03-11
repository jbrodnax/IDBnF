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

Elf64_Ehdr hdr;
Elf64_Phdr phdr;
Elf64_Shdr *shdr;

Elf64_Ehdr *elf_read_hdr(int fd, Elf64_Ehdr *hdr){
	uint32_t hdr_size;
	uint8_t MAGBUF[4] = {0x7f, 0x45, 0x4c, 0x46};

	if(!hdr){
		fprintf(stderr, "[!] Error (elf_read_hdr): null argument\n");
		exit(EXIT_FAILURE);
	}

	hdr_size = sizeof(Elf64_Ehdr);
	memset(hdr, 0, hdr_size);
	if((read(fd, hdr, hdr_size) < hdr_size)){
		printf("[!] Error reading elf header.\n");
		exit(EXIT_FAILURE);
	}

	/*Check ELF magic num*/
	if((memcmp(MAGBUF, hdr->e_ident, 4)) != 0){
		puts("[!] Error: Incorrect ELF magic number");
		exit(EXIT_FAILURE);
	}

	if(hdr->e_version == 0)
		printf("[?] Warning: ELF version is not current (e_version: %d).\n", hdr->e_version);

	/*Check Instruction Set Arch. (Machine type)*/
	switch(hdr->e_machine){
		case EM_NONE:
			puts("EM_NONE: no machine");
			break;
		case EM_M32:
			puts("EM_M32: AT&T WE 32100");
			break;
		case EM_SPARC:
			puts("EM_SPARC: SPARC");
			break;
		case EM_386:
			puts("EM_386: Intel 80386");
			break;
		case EM_68K:
			puts("EM_68K: Motorola 68000");
			break;
		case EM_88K:
			puts("EM_88K: Motorola 88000");
			break;
		case EM_860:
			puts("EM_860: Intel 80860");
			break;
		case EM_MIPS:
			puts("EM_MIPS: MIPS RS3000");
			break;
		case EM_PARISC:
			puts("EM_PARISC: HP/PA");
			break;
		case EM_SPARC32PLUS:
			puts("EM_SPARC32PLUS: SPARC with enhanced instruction set");
			break;
		case EM_PPC:
			puts("EM_PPC: PowerPC");
			break;
		case EM_PPC64:
			puts("EM_PPC64: PowerPC 64-bit");
			break;
		case EM_S390:
			puts("EM_S390: IBM S/390");
			break;
		case EM_ARM:
			puts("EM_ARM: Advanced RISC Machines");
			break;
		case EM_SH:
			puts("EM_SH: Renesas SuperH");
			break;
		case EM_SPARCV9:
			puts("EM_SPARCV9: SPARC v9 64-bit");
			break;
		case EM_IA_64:
			puts("EM_IA_64: Intel Itanium");
			break;
		case EM_X86_64:
			puts("EM_X86_64: AMD x86-64");
			break;
		case EM_VAX:
			puts("EM_VAX: DEC Vax");
			break;
		default:
			fprintf(stderr, "[!] Error (elf_read_dr): invalid e_machine value %d\n", hdr->e_machine);
			exit(EXIT_FAILURE);
	}

	/*Check ELF class*/
	switch(hdr->e_ident[EI_CLASS]){
		case ELFCLASSNONE:
			puts("ELFCLASSNONE: invalid class!");
			break;
		case ELFCLASS32:
			puts("ELFCLASS32: 32-bit object");	
			break;
		case ELFCLASS64:
			puts("ELFCLASS64: 64-bit object");
			break;
		default:
			fprintf(stderr, "[!] Error (elf_read_dr): invalid ELFCLASS value %d\n", hdr->e_ident[EI_CLASS]);
			exit(EXIT_FAILURE);
	}

	/*Check ELF type*/
	switch(hdr->e_type){
		case ET_NONE:
			puts("ET_NONE: No file type");
			break;
		case ET_REL:
			puts("ET_REL: Relocatable file");
			break;
		case ET_EXEC:
			puts("ET_EXEC: Executable file");
			break;
		case ET_DYN:
			puts("ET_DYN: Shared object file");
			break;
		case ET_CORE:
			puts("ET_CORE: Core file");
			break;
		case ET_LOPROC:
			puts("ET_LOPROC: 0xff00 (Processor Specific)");
			break;
		case ET_HIPROC:
			puts("ET_HIPROC: 0xffff (Processor Specific)");
			break;
		default:
			fprintf(stderr, "[!] Error (elf_read_dr): invalid ELFTYPE value %d\n", hdr->e_type);
			exit(EXIT_FAILURE);
	}

	/*Check ELF encoding*/
	switch(hdr->e_ident[EI_DATA]){
		case ELFDATANONE:
			puts("ELFDATANONE: invalid data encoding");
			break;
		case ELFDATA2LSB:
			puts("ELFDATA2LSB: 2's compliment, Little-endian");
			break;
		case ELFDATA2MSB:
			puts("ELFDATA2MSB: 2's compliment, Big-endian");
			break;
		default:
			fprintf(stderr, "[!] Error (elf_read_dr): invalid ELFDATA value %d\n", hdr->e_ident[EI_DATA]);
			exit(EXIT_FAILURE);
	}

	//TODO: Check OS ABI

	if(hdr->e_entry != 0){
		printf("Entry Point:\t");
		if(hdr->e_ident[EI_CLASS] == ELFCLASS32)
			printf("0x%08x\n", hdr->e_entry);
		else if(hdr->e_ident[EI_CLASS] == ELFCLASS64)
			printf("%p\n", hdr->e_entry);
	}else{
		printf("[?] Warning (elf_read_hdr): Null entry-point specified in ELF header\n");
	}

	return hdr;
}

void elf_read_phdr(int fd){

}

void elf_read_shdr(int fd, uint16_t shentsize, uint16_t shnum, Elf64_Off shoff){
	uint32_t shdr_size;
	uint16_t i;
	Elf64_Shdr *shdr;
	
	if(!(shentsize || shnum) || (shoff < 1)){
		fprintf(stderr, "[!] Error (elf_read_shdr): invalid uintN_t argument (very descriptive.. I know.)\n");
		exit(EXIT_FAILURE);
	}

	shdr_size = (shentsize * shnum);
	shdr = malloc(shdr_size);
	if(!shdr){
		perror("[!] Error (elf_read_shdr): malloc failed. ");
		exit(EXIT_FAILURE);
	}
	memset(shdr, 0, shdr_size);

	if((lseek(fd, (off_t)shoff, SEEK_SET)) < 0){
		perror("[!] Error (elf_read_shdr): lseek failed. ");
		exit(EXIT_FAILURE);
	}

	for(i=0;i<shnum;i++){
		read(fd, &shdr[i], shentsize);
		printf("0x%08x\n", shdr[i].sh_addr);
	}

	free(shdr);
	return;
}

void elf_init(int fd){
	Elf64_Ehdr *hdr_ret;
	Elf64_Off shoff;
	uint16_t shentsize, shnum;

	hdr_ret = elf_read_hdr(fd, &hdr);
	if(!hdr_ret){
		fprintf(stderr, "[!] Error (elf_init): received null hdr_ret pointer\n");
		goto FAIL;
	}
	shentsize = hdr_ret->e_shentsize;
	shnum = hdr_ret->e_shnum;
	shoff = hdr_ret->e_shoff;
	if(!shentsize || !shnum){
		fprintf(stderr, "[!] Error (elf_init): invalid e_shentsize (%" PRIu16 ") or e_shnum (%" PRIu16 ")\n", shentsize, shnum);
		goto FAIL;
	}
	if(!shoff){
		fprintf(stderr, "[!] Error (elf_init): invalid e_shoff (%" PRIu64 ")\n", shoff);
		goto FAIL;
	}
	elf_read_shdr(fd, shentsize, shnum, shoff);
	//elf_read_phdr(fd);

	FAIL: exit(EXIT_FAILURE);

	return;
}

int main(int argc, char *argv[]){
	int fd;

	if(argc != 2){
		//Usage:
		exit(1);
	}

	fd = open(argv[1], O_RDONLY);
	if(fd < 0){
		perror("[!] Failed to open file: ");
		exit(EXIT_FAILURE);
	}
	elf_init(fd);

	return 0;
}
