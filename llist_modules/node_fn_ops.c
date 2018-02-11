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
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
			puts("Subroutines:");
			for(i=0;i<fn->num_subroutines;i++){
				sub = fn->subroutines[i];
				if(!sub)
					break;	
				printf("\t%s\t(%p)\n", sub->name, (void *)sub->addr);
			}
		}
		pthread_rwlock_unlock(lock);
		return;

	REG:
		fn = node->fn;
		if(fn){
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
			puts("Subroutines:");
			for(i=0;i<fn->num_subroutines;i++){
				sub = fn->subroutines[i];
				if(!sub)
					break;
				printf("\t%s\t(%p)\n", sub->name, (void *)sub->addr);
			}
		}
		return;
}

void nfn_subroutines(list_mgr *mgr){
	node_fn *tmp_node;
	struct _fn_entry *tmp_fn;

	if(!mgr)
		return;

	pthread_rwlock_rdlock(&mgr->ll_lock);
	tmp_node = mgr->head;
	while(tmp_node){
		tmp_fn = (struct _fn_entry *)tmp_node->fn;
		printf("linking subroutines for: %s\n", tmp_fn->name);
		if((da_link_subroutines(tmp_node, mgr)) == NULL){
			puts("[!] Error nfn_subroutines: failed to find subroutines for current function.");
			//exit(EXIT_FAILURE);
		}
		tmp_node = tmp_node->next;
	}

	pthread_rwlock_unlock(&mgr->ll_lock);
	return;
}

















