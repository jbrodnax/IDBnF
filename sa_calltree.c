#include "calltrace.h"

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
	tr_root->children = malloc_s((sizeof(struct _TR_node *)*15));
	tr_root->fn = fn_root;

	new->root = tr_root;
	printf("tree manager successfully created:\nroot function: %s\n", new->root->fn->name);
	return new;
}

void sa_cleantree(treemgr_t *mgr){
	/*TODO: implement node clean up*/
	return;
}
