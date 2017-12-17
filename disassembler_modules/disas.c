#include "disas.h"

int da_disas_x86(void *data, size_t s){
	csh handle;
	cs_insn *insn;
	size_t count, i;

	if(!data || s < 1)
		return -1;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	count = cs_disasm(handle, data, s, 0x1000, 0, &insn);
	if(count > 0){
		for(i=0;i<count;i++){
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic,
				insn[i].op_str);
		}
		cs_free(insn, count);
	}else{
		printf("[!] Error: in da_disas_x86. Failed to disassemble data.\n");
	}

	cs_close(&handle);
	return 0;
}

int da_disas_fn(struct _fn_entry *f){
	csh handle;
	cs_insn *insn;
	size_t count;

	if(!f)
		return -1;

	puts("Finish");

	return 0;
}

int main(int argc, char *argv[]){
	char test1[] = {0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00};
	void *ptr = &test1;
	if((da_disas_x86(ptr, 8)) < 0)
		printf("[!] test1 failed.\n");

	return 0;
}
