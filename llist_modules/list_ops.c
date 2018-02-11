#include "../calltrace.h"

list_mgr *ll_init_manager(){
	list_mgr *new;

	new = malloc_s(sizeof(list_mgr));
	if(pthread_rwlock_init(&new->ll_lock, NULL) != 0){
		perror("[!] Error in ll_init_manager: pthread_rwlock init failed. ");
		exit(EXIT_FAILURE);
	}

	return new;
}

int ll_destroy(list_mgr *mgr){
	if(!mgr)
		return -1;
	if((ll_clean(mgr)) != 0){
		printf("[!] Error in ll_destroy: failed to clean list.\n");
		return -1;
	}

	free(mgr);
	return 0;
}

node_fn *ll_add(void *data, list_mgr *mgr){
/*
* Init new node_fn and append to tail of list.
*/

	node_fn *new_node;

	if(!data || !mgr)
		return NULL;

	new_node = malloc_s(sizeof(node_fn));
	new_node->fn = data;

	pthread_rwlock_wrlock(&mgr->ll_lock);
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

	pthread_rwlock_unlock(&mgr->ll_lock);
	return new_node;
}

int ll_remove(node_fn *node, list_mgr *mgr){
/*
* ulink and free given node_fn.
*/
	if(!node || !mgr)
		return -1;

	pthread_rwlock_wrlock(&mgr->ll_lock);
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

	pthread_rwlock_unlock(&mgr->ll_lock);
	return 0;
}

//FIX: add list type checking to ensure sub-structs of node are freed
int ll_clean(list_mgr *mgr){
/*
* Clean entire list managed by passed list_mgr 
*/
	node_fn *tmp1, *tmp2;
	struct _fn_entry *fn;

	if(!mgr)
		return -1;

	pthread_rwlock_wrlock(&mgr->ll_lock);
	tmp1 = mgr->head;
	while(tmp1){
		if(tmp1->fn){
			fn = (struct _fn_entry *)tmp1->fn;
			if(fn->data)
				free(fn->data);
			if(fn->subroutines)
				free(fn->subroutines);
			free(tmp1->fn);
		}
		tmp2 = tmp1;
		tmp1 = tmp1->next;
		free(tmp2);
	}

	pthread_rwlock_unlock(&mgr->ll_lock);
	return 0;
}











