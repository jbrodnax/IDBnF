#include "../calltrace.h"

node_fn *nfn_search(uint64_t addr, char *name, list_mgr *mgr){
/*
* Traverse list and search for fn_entry based on start address
* or function name.
*/
	node_fn *tmp;
	struct _fn_entry *fn;

	if(!mgr){
		printf("[!] Error in nfn_search: NULL list_mgr\n");
		return NULL;
	}

	pthread_rwlock_rdlock(&mgr->ll_lock);
	if(addr != 0){
		tmp = mgr->head;	
		while(tmp){
			if(tmp->fn != NULL){
				fn = (struct _fn_entry *)tmp->fn;	
				if(fn->addr == addr)
					goto RET;
			}
			tmp = tmp->next;
		}
		goto RET;
	}else if(name != NULL){
		tmp = mgr->head;
		while(tmp){
			if(tmp->fn != NULL){
				fn = (struct _fn_entry *)tmp->fn;
				if((memcmp(name, fn->name, strlen(fn->name))) == 0)
					goto RET;
			}
			tmp = tmp->next;
		}
		goto RET;
	}

	RET:
		pthread_rwlock_unlock(&mgr->ll_lock);
		return tmp;
}

node_fn * nfn_plt_search(uint64_t call_addr, list_mgr *mgr){
/* Used for validating and updating possible PLT function addresses.
* load_funcs.py returns PLT function addresses as the ending address of the PLT entry.
* This will update the _fn_entry info accordingly.
* call_addr is the address parameter for the call instruction in question.
*/
	node_fn *tmp;
	struct _fn_entry *fn;
	uint64_t offset;

	if(!mgr)
		return NULL;

	printf("[*] DEBUG nfn_plt_search: called with arg1 = %p\n", call_addr);
	pthread_rwlock_wrlock(&mgr->ll_lock);

	tmp = mgr->head;
	while(tmp){	
		if(tmp->fn != NULL){
			fn = (struct _fn_entry *)tmp->fn;
			printf("[*] DEBUG nfn_plt_search: checking function (%s)\n", fn->name);
			if(fn->fn_plt != NULL){
				offset = call_addr - fn->addr;
				if(offset == 0x10)	
					goto UPDATE;
			}
		}
		tmp = tmp->next;
	}
	goto RET;

	UPDATE:
		printf("[*] DEBUG nfn_plt_search: function (%s) has PLT entry @ %p\n", fn->name, call_addr);
		fn->addr = call_addr;
		fn->fn_plt->plt_addr = call_addr;
		//TODO: add got_addr calculation
		goto RET;

	RET:
		puts("[*] DEBUG nfn_plt_search: returning.\n");
		pthread_rwlock_unlock(&mgr->ll_lock);
		return tmp;
}

void nfn_display_all(list_mgr *mgr){
/*
* Thread-safe method for printing data for all function-nodes in a linked-list
*/
	node_fn *tmp;
	struct _fn_entry *fn;

	if(!mgr)
		return;

	pthread_rwlock_rdlock(&mgr->ll_lock);
	tmp = mgr->head;
	while(tmp){
		nfn_display(tmp, NULL);
		fn = (struct _fn_entry *)tmp->fn;
		if(fn->data)
			da_disas_fn(fn);
		tmp = tmp->next;
	}

	pthread_rwlock_unlock(&mgr->ll_lock);
	return;
}

void nfn_display(node_fn *node, pthread_rwlock_t *lock){
/*
* Print node-associated function information to console.
*/
	struct _fn_entry *fn;
	struct _fn_entry *sub;
	int i;

	if(!node)
		return;

	if(lock)
		goto LOCK;
	else
		goto REG;

	LOCK:
		pthread_rwlock_rdlock(lock);
		fn = node->fn;
		if(fn){
			puts("\n********************************");
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
			puts("Subroutines:");
			for(i=0;i<fn->num_subroutines;i++){
				sub = fn->subroutines[i];
				if(!sub)
					break;	
				printf("\t%s\t(%p)\n", sub->name, (void *)sub->addr);
			}
			puts("********************************");
		}
		pthread_rwlock_unlock(lock);
		return;

	REG:
		fn = node->fn;
		if(fn){
			puts("\n********************************");
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
			puts("Subroutines:");
			for(i=0;i<fn->num_subroutines;i++){
				sub = fn->subroutines[i];
				if(!sub)
					break;
				printf("\t%s\t(%p)\n", sub->name, (void *)sub->addr);
			}
			puts("********************************");
		}
		return;
}

void nfn_subroutines(list_mgr *mgr){
	node_fn *tmp_node;
	node_fn *subs_node;
	struct _fn_entry *tmp_fn;
	uint64_t *call_addrs;
	uint64_t num_subs, i;

	if(!mgr)
		return;

	pthread_rwlock_wrlock(&mgr->ll_lock);
	tmp_node = mgr->head;
	while(tmp_node){
		tmp_fn = (struct _fn_entry *)tmp_node->fn;
		if(tmp_fn->fn_plt){
			tmp_node = tmp_node->next;
			continue;
		}

		tmp_fn->subroutines = malloc_s((sizeof(struct _fn_entry *))*MAX_SUBROUTINES);
		tmp_fn->num_subroutines = 0;

		printf("linking subroutines for: %s\n", tmp_fn->name);
		call_addrs = da_link_subroutines(tmp_node, mgr);
		memcpy(&num_subs, call_addrs, sizeof(uint64_t));

		printf("[*] DEBUG nfn_subroutines: num_subs = %u\n", num_subs);
		if(num_subs >= MAX_SUBROUTINES){
			printf("[!] Error nfn_subroutines: function (%s) has too many subroutines (%u).\n", tmp_fn->name, num_subs);
			exit(0);
		}
		for(i=0;i<num_subs;i++){
			//TODO: find better method of managing rwlocks for inter-node_fn_ops functio calls
			pthread_rwlock_unlock(&mgr->ll_lock);
			subs_node = nfn_search(call_addrs[i+1], NULL, mgr);
			pthread_rwlock_wrlock(&mgr->ll_lock);
			if(subs_node == NULL){	
				pthread_rwlock_unlock(&mgr->ll_lock);
				nfn_plt_search(call_addrs[i+1], mgr);
				pthread_rwlock_wrlock(&mgr->ll_lock);
			}
			if(subs_node != NULL){
				tmp_fn->subroutines[tmp_fn->num_subroutines] = (struct _fn_entry *)subs_node->fn;
				tmp_fn->num_subroutines++;
			}
		}
		free(call_addrs);
		tmp_node = tmp_node->next;
	}

	pthread_rwlock_unlock(&mgr->ll_lock);
	return;
}

void nfn_subroutines_display(struct _fn_entry *entry_pt, uint8_t lvl, list_mgr *mgr){
	node_fn *current;
	struct _fn_entry *tmp1;
	int i, l;

	tmp1 = entry_pt;
	if(!tmp1)
		return;

	if(lvl == 0){
		pthread_rwlock_rdlock(&mgr->ll_lock);
		puts("Call Tree: [lvl] name (#subs)");
	}

	for(l=0;l<lvl;l++)
		write(1,"\t",1);

	printf("[%d] %s (%d)\n", lvl, tmp1->name, tmp1->num_subroutines);
	for(i=0;i<tmp1->num_subroutines;i++)
		nfn_subroutines_display(tmp1->subroutines[i], lvl+1, mgr);

	if(lvl == 0)
		pthread_rwlock_unlock(&mgr->ll_lock);

	return;
}















