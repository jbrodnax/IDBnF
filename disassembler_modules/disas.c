#include "disas.h"

int da_init_platform(char *arch, uint8_t da_flavor){
	size_t n;

	n = strlen(arch);
	if(n < 1){
		puts("[!] Error in da_init_platform: invalid strlen for arch.");
		return -1;
	}

	memset(&da_platform, 0, sizeof(struct platform));

	if((memcmp(arch, "amd64", 5)) == 0){
		da_platform.arch = CS_ARCH_X86;
		da_platform.mode = CS_MODE_64;
	}else{
		puts("[!] Error in da_init_platform: unsupported arch type.");
		return -1;
	}

	if(da_flavor != 0){
		da_platform.opt_type = CS_OPT_SYNTAX;
		da_platform.opt_value = CS_OPT_SYNTAX_ATT;
	}

	if(cs_open(da_platform.arch, da_platform.mode, &handle) != CS_ERR_OK)
		return -1;

	return 0;
}

void da_destroy_platform(){
	cs_close(&handle);
}

int da_disas_x86(void *data, uint64_t addr, size_t sz){
	csh handle;
	cs_insn *insn;
	uint64_t start_addr;
	size_t count, i;

	if(!data || sz < 1)
		return -1;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	if(da_platform.opt_type){
		cs_option(handle, da_platform.opt_type, da_platform.opt_value);
	}

	if(addr == 0)
		start_addr = 0x1000;
	else
		start_addr = addr;

	count = cs_disasm(handle, data, sz, start_addr, 0, &insn);
	if(count > 0){
		for(i=0;i<count;i++){
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
			/*if(insn[i].bytes[0] >= MIN_JOP && insn[i].bytes[0] <= MAX_JOP){
				printf("[!] Jump instruction @ 0x%08x\n", insn[i].address);
			}else if(insn[i].bytes[0] == CALL){
				printf("[!] Call instruction found at address: 0x%08x\n", insn[i].address);
			}*/
		}
		cs_free(insn, count);
	}else{
		printf("[!] Error: in da_disas_x86. Failed to disassemble data.\n");
	}

	//cs_close(&handle);
	return 0;
}
/*
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
*/
struct _fn_entry ** da_link_subroutines(node_fn *node, list_mgr *lmgr){
	struct _fn_entry *tmp;
	struct _fn_entry *fn;
	node_fn *tmp_node;
	//csh handle;
	cs_insn *insn;
	uint64_t start_addr, addr, call_addr_op;
	size_t count, i, sz;
	void *data;
	cs_x86 *x86;

	if(!node || !lmgr){
		puts("[!] Error in da_link_subroutines: recieved NULL argument");
		exit(EXIT_FAILURE);
	}

	//pthread_rwlock_rdlock(&fn_lock1);
	tmp = (struct _fn_entry *)node->fn;
	data = tmp->data;
	addr = tmp->addr;
	sz = tmp->size;

	tmp->subroutines = malloc_s((sizeof(struct _fn_entry *)*MAX_SUBROUTINES));
	tmp->num_subroutines = 0;

	if(!data || sz < 1)
		return NULL;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return NULL;

	if(addr == 0)
		start_addr = 0x1000;
	else
		start_addr = addr;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	if((count = cs_disasm(handle, data, sz, start_addr, 0, &insn)) < 1){
		printf("[!] Error: in da_link_subroutines. Failed to disassemble data.\n");
		return NULL;
	}
	for(i=0;i<count;i++){
		if(insn[i].bytes[0] == CALL){
			x86 = &(insn[i].detail->x86);
			cs_x86_op *op = &(x86->operands[0]);
			if((int)op->type == X86_OP_IMM){
				call_addr_op = op->imm;
				//printf("Instruction calls address: 0x%" PRIx64 "\n", call_addr_op);
				tmp_node = nfn_search(call_addr_op, NULL, lmgr);
				if(tmp_node != NULL){
					fn = (struct _fn_entry *)tmp_node->fn;
					//printf("Function name: %s\n", fn->name);
					tmp->subroutines[tmp->num_subroutines] = fn;
					tmp->num_subroutines++;
				}
			}else{
				printf("[!] Error: x86 call instruction is non-IMM\n");
				return NULL;
			}	
		}
	}

	//pthread_rwlock_unlock(&fn_lock1);
	return tmp->subroutines;
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










