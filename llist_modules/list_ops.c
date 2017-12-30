#include "../calltrace.h"

node_fn *ll_add(void *data, list_mgr *mgr){
/*
* Init new node_fn and append to tail of list.
*/

	node_fn *new_node;

	if(!data || !mgr)
		return NULL;

	new_node = malloc_s(sizeof(node_fn));
	new_node->fn = data;

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

int ll_remove(node_fn *node, list_mgr *mgr){
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

//FIX: add list type checking to ensure sub-structs of node are freed
int ll_clean(list_mgr *mgr){
/*
* Clean entire list managed by passed list_mgr 
*/
	node_fn *tmp1, *tmp2;
	struct _fn_entry *fn;

	if(!mgr)
		return -1;

	pthread_rwlock_wrlock(&fn_lock1);
	tmp1 = mgr->head;
	while(tmp1){
		if(tmp1->fn){
			fn = (struct _fn_entry *)tmp1->fn;
			if(fn->data)
				free(fn->data);
			free(tmp1->fn);
		}
		tmp2 = tmp1;
		tmp1 = tmp1->next;
		free(tmp2);
	}
	memset(mgr, 0, sizeof(list_mgr));

	pthread_rwlock_unlock(&fn_lock1);

	return 0;
}











