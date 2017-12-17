CC=gcc
CFLAGSDB=-Wall -W -g -Werror
CFLAGS=-pthread
LDIR=llist_modules/
DDIR=disassembler_modules/
LIBCAP=capstone

all: calltrace

calltrace: calltrace.c $(LDIR)node_fn_ops.c $(DDIR)disas.c
	$(CC) calltrace.c $(LDIR)node_fn_ops.c $(DDIR)disas.c -l$(LIBCAP) $(CFLAGS) -o calltrace

clean:
	rm -f calltrace *.o
