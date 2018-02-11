#include "calltrace.h"

list_mgr *fn_mgr;
list_mgr stc_calltree;
struct _trace_proc tproc;

void *malloc_s(size_t s){
	void *p;
	if((p = malloc(s)) == NULL){
		perror("[!] Error in malloc ");
		exit(EXIT_FAILURE);
	}
	memset(p, 0, s);
	return p;
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

	/*Get file size and read file into heap-buf*/
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

	/*Check initial magic number*/
	memcpy(&magicnum, input, sizeof(int));
	if(magicnum != MAGICNUM){
		printf("[!] Error: in loadfuncs. Invalid file type.\n");
		exit(EXIT_FAILURE);
	}
	memcpy(&numfns, &input[sizeof(int)+1], sizeof(int));
	printf("Number of symbols: %d\n", numfns);

	/*Allocate space for function nodes of LList and read in all function symbols*/
	offset = FRST_FN;
	while(numfns > 0){
		if(offset >= fsize)
			return 0;

		f = malloc_s(sizeof(struct _fn_entry));
		memcpy(f, &input[offset], sizeof(struct _fn_entry));
		offset+=FN_HDR_SIZE;

		f->data = malloc_s(f->size);
		memcpy(f->data, &input[offset], f->size);
		
		ll_add(f, fn_mgr);
		offset+=f->size+1;
		numfns--;
	}

	/*Add plt functions to end of LList*/
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
		//nfn_add(f, &fn_mgr);
		ll_add(f, fn_mgr);
		offset+=(FN_NAME+FN_ADDR)+1;
	}

	return 0;
}

int main(int argc, char *argv[]){
	char *filename;
	size_t fs1, fs2;

	if(argc != 3){
		printf("Usage: %s <binary file> <function file>\n", argv[0]);
		exit(0);
	}

	fs1 = strlen(argv[1]);
	if(fs1 < 1){
		printf("Invalid binary file name.\n");
		exit(1);
	}

	fs2 = strlen(argv[2]);
	if(fs2 < 1){
		printf("Invalid function file name.\n");
		exit(1);
	}

	if(da_init_platform("amd64", 0) != 0){
		puts("[!] Error: failed to init disassembly platform.");
		exit(EXIT_FAILURE);
	}

	fn_mgr = ll_init_manager();
	filename = argv[2];
	loadfns(filename);
	nfn_subroutines(fn_mgr);
	nfn_display_all(fn_mgr);

	node_fn *_entry = nfn_search(0, "main", fn_mgr);
	if(_entry){	
		struct _fn_entry *entry = (struct _fn_entry *)_entry->fn;
		nfn_subroutines_display(entry, 0, fn_mgr);
	}

	/*memset(&tproc, 0, sizeof(struct _trace_proc));
	tproc.name = malloc_s(fs1+1);
	strncpy(tproc.name, argv[1], (fs1+1));
	init_trace(&tproc);*/

	ll_destroy(fn_mgr);
	da_destroy_platform();
	
	return 0;
}
