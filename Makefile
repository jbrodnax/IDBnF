CC=gcc
CFLAGSDB=-Wall -W -g -Werror
CFLAGS=-pthread
LDIR=llist_modules/
DDIR=disassembler_modules/
TDIR=trace_modules/
LIBCAP=capstone

all: mainv1

mainv1: main_v1.c $(LDIR)list_ops.c $(LDIR)node_fn_ops.c $(DDIR)disas.c $(TDIR)trace.c sa_calltree.c
	$(CC) main_v1.c $(LDIR)list_ops.c $(LDIR)node_fn_ops.c $(DDIR)disas.c $(TDIR)trace.c sa_calltree.c -l$(LIBCAP) $(CFLAGS) -o main_v1

clean:
	rm -f main_v1 *.o
