CC=gcc
CFLAGSDB=-Wall -W -g -Werror
CFLAGS=-g -o

all: elf_reader test_run

elf_reader: elf_reader_v2.c
	$(CC) -o elf_rdr.o -c elf_reader_v2.c

test_run: test_run.c
	$(CC) test_run.c -o test_run elf_rdr.o 

clean:
	rm -f elf_rdr *.o; rm -f test_run *.o
