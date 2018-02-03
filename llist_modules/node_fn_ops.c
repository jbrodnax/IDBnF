#include "../calltrace.h"

node_fn *nfn_search(uint64_t addr, char *name, list_mgr *mgr){
/*
* Traverse list and search for fn_entry based on start address
* or function name.
*/
	node_fn *tmp;
	struct _fn_entry *fn;

	if(!mgr)
		return NULL;
	if(mgr->type != LTYPE_FNE)
		return NULL;

	pthread_rwlock_rdlock(&fn_lock1);
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
		pthread_rwlock_unlock(&fn_lock1);
		return tmp;
}

struct _TR_mgr * init_static_calltree(struct _TR_mgr *mgr, struct _fn_entry *fn_root){
	struct _TR_mgr *new;

	if(!fn_root)
		return NULL;

	if(!mgr){
		new = malloc_s(sizeof(struct _TR_mgr));
		mgr = new;
	}

	

}

struct _TR_node * build_calltree(struct _fn_entry *start){
	struct _TR_node *root;

	if(!start)
		return NULL;

	root = malloc_s(sizeof(struct _TR_node));

	return root;
}

void nfn_display_all(list_mgr *mgr){
/*
* Thread-safe method for printing data for all function-nodes in a linked-list
*/
	node_fn *tmp;
	struct _fn_entry *fn;

	if(!mgr)
		return;

	pthread_rwlock_rdlock(&fn_lock1);
	tmp = mgr->head;
	while(tmp){
		nfn_display(tmp, NULL);
		fn = (struct _fn_entry *)tmp->fn;
		if(fn->data)
			da_disas_fn(fn);
		tmp = tmp->next;
	}

	pthread_rwlock_unlock(&fn_lock1);
	return;
}

void nfn_display(node_fn *node, pthread_rwlock_t *lock){
/*
* Print node-associated function information to console.
*/
	struct _fn_entry *fn;

	if(!node)
		return;

	if(lock)
		goto LOCK;
	else
		goto REG;

	LOCK:
		pthread_rwlock_rdlock(lock);
		fn = node->fn;
		if(fn)
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
		pthread_rwlock_unlock(lock);
		return;

	REG:
		fn = node->fn;
		if(fn)
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, (void *)fn->addr, fn->size);
		return;
}




