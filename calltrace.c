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
		if(tmp1->fn)
			free(tmp1->fn);
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
		tmp = tmp->next;
	}

	pthread_rwlock_unlock(&fn_lock1);
	return;
}

int loadfns(char *fname){
	long int fsize;
	int magicnum;
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
	}
	//printf("Received magic num: %d (0x%08x)\n", magicnum, magicnum);

	for(offset=FRST_FN;offset<fsize;offset+=NEXT_FN){
		f = malloc_s(sizeof(struct _fn_entry));	
		memcpy(f, &input[offset], sizeof(struct _fn_entry));
		nfn_add(f, &fn_mgr);
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



