CC=gcc
CFLAGSDB=-Wall -W -g -Werror
CFLAGS=-pthread
LDIR=llist_modules/

all: calltrace

calltrace: calltrace.c $(LDIR)node_fn_ops.c
	$(CC) calltrace.c $(LDIR)node_fn_ops.c $(CFLAGS) -o calltrace

clean:
	rm -f calltrace *.o
