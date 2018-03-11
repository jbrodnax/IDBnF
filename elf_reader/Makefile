CC=gcc
CFLAGSDB=-Wall -W -g -Werror
CFLAGS=-g -o

all: elf_reader

elf_reader: elf_reader.c 
	$(CC) elf_reader.c $(CFLAGS) elf_reader

clean:
	rm -f elf_reader *.o
