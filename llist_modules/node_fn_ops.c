#include "../calltrace.h"

node_fn *nfn_add(struct _fn_entry *fn, struct _fn_mgr *mgr){
/*
* Init new node_fn and append to tail of list.
*/
	node_fn *new_node;

	if(!fn || !mgr)
		return NULL;

	new_node = malloc_s(sizeof(node_fn));
	new_node->fn = fn;

	pthread_rwlock_wrlock(&fn_lock1);
	if(mgr->head == NULL){
		mgr->head = new_node;
		mgr->tail = new_node;
		mgr->list_size = 1;
	}else if(mgr->tail != NULL){
		mgr->tail->next = new_node;
		new_node->prev = mgr->tail;
		mgr->tail = new_node;
	}else{
		free(new_node);
		new_node = NULL;
	}

	pthread_rwlock_unlock(&fn_lock1);
	return new_node;
}

node_fn *nfn_search(uint64_t addr, char *name, struct _fn_mgr *mgr){
/*
* Traverse list and search for fn_entry based on start address
* or function name.
*/
	node_fn *tmp = NULL;

	if(!mgr)
		return tmp;

	pthread_rwlock_rdlock(&fn_lock1);
	if(addr != 0){
		tmp = mgr->head;
		while(tmp){
			if(tmp->fn != NULL){
				if(tmp->fn->addr == addr)
					goto RET;
			}
			tmp = tmp->next;
		}
		goto RET;
	}else if(name != NULL){
		tmp = mgr->head;
		while(tmp){
			if(tmp->fn != NULL){
				if((memcmp(name, tmp->fn->name, strlen(tmp->fn->name))) == 0)
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

int nfn_remove(node_fn *node, struct _fn_mgr *mgr){
/*
* ulink and free given node_fn.
*/
	if(!node || !mgr)
		return -1;

	pthread_rwlock_wrlock(&fn_lock1);
	if(node->next && node->prev){
		node->next->prev = node->prev;
		node->prev->next = node->next;
	}else if(node->next && !node->prev){
		node->next->prev = NULL;
		mgr->head = node->next;
	}else if(!node->next && node->prev){
		node->prev->next = NULL;
		mgr->tail = node->prev;
	}else{
		mgr->head = NULL;
		mgr->tail = NULL;
	}

	mgr->list_size--;
	free(node);

	pthread_rwlock_unlock(&fn_lock1);
	return 0;
}

void nfn_display_fn(node_fn *node, pthread_rwlock_t *lock){
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
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, fn->addr, fn->size);
		pthread_rwlock_unlock(lock);
		return;

	REG:
		fn = node->fn;
		if(fn)
			printf("[*] Function Data\nName:\t\t%s\nAddr:\t\t%p\nSize:\t\t%d\n", fn->name, fn->addr, fn->size);
		return;
}




