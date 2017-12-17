#include "calltrace.h"

struct _fn_mgr fn_mgr;

void *malloc_s(size_t s){
	void *p;
	if((p = malloc(s)) == NULL){
		perror("[!] Error in malloc ");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, s);
	return p;
}

void clean_fn_list(struct _fn_mgr *mgr){
	node_fn *tmp1, *tmp2;

	if(!mgr)
		return;

	pthread_rwlock_wrlock(&fn_lock1);
	tmp1 = mgr->head;
	while(tmp1){
		if(tmp1->fn){
			if(tmp1->fn->data)
				free(tmp1->fn->data);
			free(tmp1->fn);
		}
		tmp2 = tmp1;
		tmp1 = tmp1->next;
		free(tmp2);
	}
	memset(mgr, 0, sizeof(struct _fn_mgr));

	pthread_rwlock_unlock(&fn_lock1);
	return;
}

void display_fn_list(struct _fn_mgr *mgr){
	node_fn *tmp;

	if(!mgr)
		return;

	pthread_rwlock_rdlock(&fn_lock1);
	tmp = mgr->head;
	while(tmp){
		nfn_display_fn(tmp, NULL);
		if(tmp->fn->data)
			da_disas_fn(tmp->fn);
		tmp = tmp->next;
	}

	pthread_rwlock_unlock(&fn_lock1);
	return;
}

int loadfns(char *fname){
	long int fsize;
	int magicnum, numfns;
	uint32_t offset;
	FILE *fp;
	char *input;
	struct _fn_entry *f;

	if(!(fp = fopen(fname, "r"))){
		perror("[!] Error: ");
		exit(EXIT_FAILURE);
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);
	if(fsize < 1){
		printf("[!] Error: in loadfuncs. Invalid file size.\n");
		exit(EXIT_FAILURE);
	}

	input = malloc_s(fsize);
	if((fread(input, fsize, 1, fp)) < 1){
		perror("[!] Error: ");
		exit(EXIT_FAILURE);
	}
	fclose(fp);
	memcpy(&magicnum, input, sizeof(int));
	if(magicnum != MAGICNUM){
		printf("[!] Error: in loadfuncs. Invalid file type.\n");
		exit(EXIT_FAILURE);
	}
	memcpy(&numfns, &input[sizeof(int)+1], sizeof(int));
	printf("Number of symbols: %d\n", numfns);

	offset = FRST_FN;
	while(numfns > 0){
		if(offset >= fsize)
			return 0;

		f = malloc_s(sizeof(struct _fn_entry));	
		memcpy(f, &input[offset], sizeof(struct _fn_entry));
		offset+=FN_HDR_SIZE;

		f->data = malloc_s(f->size);
		memcpy(f->data, &input[offset], f->size);
		nfn_add(f, &fn_mgr);
		offset+=f->size+1;
		numfns--;
	}

	memcpy(&magicnum, &input[offset], sizeof(int));
	if(magicnum != MAGICPLT){
		printf("[!] Error: in loadfuncs. Invalid plt id.\n");
		exit(EXIT_FAILURE);
	}

	offset+=(sizeof(int)+1);
	while(offset < fsize){
		f = malloc_s(sizeof(struct _fn_entry));
		memcpy(f, &input[offset], (FN_NAME+FN_ADDR));
		f->fn_plt = malloc_s(sizeof(struct _fn_plt));
		f->fn_plt->plt_addr = f->addr;
		nfn_add(f, &fn_mgr);
		offset+=(FN_NAME+FN_ADDR)+1;
	}

	return 0;
}

int main(int argc, char *argv[]){
	char *filename;

	if(argc != 3){
		printf("Usage: %s <binary file> <function file>\n", argv[0]);
		exit(0);
	}

	memset(&fn_mgr, 0, sizeof(struct _fn_mgr));
	filename = argv[2];
	loadfns(filename);
	display_fn_list(&fn_mgr);
	clean_fn_list(&fn_mgr);
	return 0;
}



