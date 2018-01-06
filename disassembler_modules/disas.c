#include "disas.h"

int da_disas_x86(void *data, uint64_t addr, size_t sz){
	csh handle;
	cs_insn *insn;
	uint64_t start_addr;
	size_t count, i;

	if(!data || sz < 1)
		return -1;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	if(addr == 0)
		start_addr = 0x1000;
	else
		start_addr = addr;

	count = cs_disasm(handle, data, sz, start_addr, 0, &insn);
	if(count > 0){
		for(i=0;i<count;i++){
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
			if(insn[i].bytes[0] >= MIN_JOP && insn[i].bytes[0] <= MAX_JOP){
				printf("[!] Jump instruction @ 0x%08x\n", insn[i].address);
			}else if(insn[i].bytes[0] == CALL){
				printf("[!] Call instruction found at address: 0x%08x\n", insn[i].address);
			}
		}
		cs_free(insn, count);
	}else{
		printf("[!] Error: in da_disas_x86. Failed to disassemble data.\n");
	}

	cs_close(&handle);
	return 0;
}

uint64_t find_x86_call(void *data, uint64_t addr, size_t sz){
	csh handle;
	cs_insn *insn;
	uint64_t start_addr;
	size_t count, i;

	if(!data || sz < 1)
		return -1;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	if(addr == 0)
		start_addr = 0x1000;
	else
		start_addr = addr;

	count = cs_disasm(handle, data, sz, start_addr, 0, &insn);
	if(count > 0){
		for(i=0;i<count;i++){
			//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
			if(insn[i].bytes[0] == CALL){
				printf("[!] Call instruction found at address: 0x%08x\n", insn[i].address);
			}
		}
		cs_free(insn, count);
	}else{
		printf("[!] Error: in da_disas_x86. Failed to disassemble data.\n");
	}

	cs_close(&handle);
	return 0;
}

int da_disas_fn(struct _fn_entry *f){
	if(!f)
		return -1;
	if(f->data){
		printf("<<\tBEGIN %s disassembly\t>>\n", f->name);
		da_disas_x86(f->data, f->addr, f->size);
		printf("<<\tEND %s disassembly\t>>\n\n", f->name);
	}
	return 0;
}
