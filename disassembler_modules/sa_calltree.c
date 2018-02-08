#include "disas.h"

treemgr_t * init_sa_calltree(struct _fn_entry *fn_root){
	treemgr_t *new;
	struct _TR_node *tr_root;

	if(!fn_root)
		return NULL;

	new = malloc_s(sizeof(treemgr_t));
	if(pthread_rwlock_init(&new->tr_lock, NULL) != 0){
		perror("[!] tree manager rw_lock initialization: ");
		exit(EXIT_FAILURE);
	}

	tr_root = malloc_s(sizeof(struct _TR_node));
	/*FIX: change hardcoded array size of 15*/
	tr_root->children = malloc_s((sizeof(struct _TR_node *)*MAX_CHILDREN));
	tr_root->fn = fn_root;

	new->root = tr_root;
	printf("tree manager successfully created:\nroot function: %s\n", new->root->fn->name);
	return new;
}

void sa_cleantree(treemgr_t *mgr){
	/*TODO: implement node clean up*/
	return;
}

struct _TR_node *sa_init_TRnode(struct _fn_entry *f, struct _TR_node *parent, treemgr_t *mgr){
	struct _TR_node *new;

	/*TODO: make function thread-safe?*/
	if(f == NULL || parent == NULL || mgr == NULL){
		printf("[!] Error in sa_init_TRnode: recieved NULL argument.\n");
		exit(EXIT_FAILURE);
	}

	new = malloc_s(sizeof(struct _TR_node));
	new->children = malloc_s((sizeof(struct _TR_node *)*MAX_CHILDREN));
	new->fn = f;
	new->parent = parent;

	return new;
}

int sa_calltree(struct _TR_node *node, list_mgr *lmgr, treemgr_t *mgr){
	struct _TR_node *current;
	node_fn *lnode;
	struct _fn_entry *fn;
	csh handle; 
	cs_insn *insn;
	uint64_t addr, start_addr, call_addr_op;
	size_t count, i, sz;
	void *data;
	cs_x86 *x86;

	if(node == NULL || mgr == NULL){
		printf("[!] Error sa_calltree received NULL argument\n");
		exit(EXIT_FAILURE);
	}else if(node->fn == NULL){
		return -1;
	}

	current = node;
	data = current->fn->data;
	addr = current->fn->addr;
	sz = current->fn->size;

	if(!data || sz < 1)
		return -1;

	if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	if(addr == 0)
		start_addr = 0x1000;
	else
		start_addr = addr;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, data, sz, start_addr, 0, &insn);

	if(count > 0){
		for(i=0;i<count;i++){
			if(insn[i].bytes[0] == CALL){
				x86 = &(insn[i].detail->x86);
				cs_x86_op *op = &(x86->operands[0]);
				if((int)op->type == X86_OP_IMM){
					call_addr_op = op->imm;
					//printf("Instruction calls address: 0x%" PRIx64 "\n", call_addr_op);
					lnode = nfn_search(call_addr_op, NULL, lmgr);
					if(lnode != NULL){
						fn = (struct _fn_entry *)lnode->fn;
						//printf("Function name: %s\n", fn->name);
						current = sa_addchild(current, fn, mgr);
						sa_calltree(current, lmgr, mgr);
					}
				}else{
					printf("[!] Error: x86 call instruction is non-IMM\n");
					return -1;
				}	
			}
		}
		cs_free(insn, count);
	}else{
		printf("[!] Error: in da_disas_x86. Failed to disassemble data.\n");
	}

	cs_close(&handle);
	return 0;
}

struct _TR_node *sa_addchild(struct _TR_node *parent, struct _fn_entry *f, treemgr_t *mgr){
	struct _TR_node *new_child;

	if(parent == NULL || f == NULL || mgr == NULL){
		printf("[!] Error sa_addchild received NULL argument\n");
		return NULL;
	}

	pthread_rwlock_wrlock(&mgr->tr_lock);
	if(parent->num_children >= MAX_CHILDREN){
		printf("[!] Error: tree node has max children. Child not added.\n");
		return NULL;
	}
	/*Create new child, add fn entry, link parent and child*/
	new_child = sa_init_TRnode(f, parent, mgr);
	parent->children[parent->num_children] = new_child;
	parent->num_children++;
	mgr->depth++;

	pthread_rwlock_unlock(&mgr->tr_lock);
	return new_child;
}

void sa_printfn_xrefs(struct _TR_node *c){
	struct _TR_node *tmp;
	int i;

	printf("%s calls:\n", c->fn->name);
	for(i=0; i<c->num_children; i++){
		printf("%s\n", c->children[i]->fn->name);
	}
	return;
}





