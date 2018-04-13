#include "elf_reader.h"

int main(int argc, char **argv){
	elf_info *ei_table;
	Elf64_Shdr *search_res;
	Elf64_Sym *sym_search;
	unsigned char *instrs;
	uint64_t i;

	ei_table = elf_init(argv[1]);
	if(!ei_table)
		return -1;

	elf_print_sections(ei_table);
	elf_print_symbols(ei_table, SHT_SYMTAB);
	elf_print_symbols(ei_table, SHT_DYNSYM);
	if((search_res = elf_section_search(ei_table, ".text", 0)))
		printf("[*] Section Search returned:\n0x%"PRIx64"\n", search_res->sh_addr);	
	if((sym_search = elf_symbol_search(ei_table, "func1", 0))){
		printf("[*] Symbol Search returned:\nName:\t%s\tAddress:\t0x%"PRIx64"\n",
			(ei_table->stc_sym_names + sym_search->st_name),
			sym_search->st_value);
	}
	if((instrs = elf_get_symbol_instructions(ei_table, sym_search))){
		printf("[*] Opcodes for %s (0x%"PRIx64"):\n", (ei_table->stc_sym_names + sym_search->st_name), sym_search->st_value);
		for(i=0;i<sym_search->st_size;i++){
			printf("%02x ", instrs[i]);
		}
		puts("");
	}

	elf_fini(ei_table);

	return 0;
}
