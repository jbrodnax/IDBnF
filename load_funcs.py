from pwn import *
import sys

def print_funcs(f):
	print "Name: "+f.name+"\tAddr: "+hex(f.address)+"\tSize: "+str(f.size)+"\n"
	return

def write_funcs(elf):
	flname	= "ftable.txt"
	fdic	= elf.functions
	fd	= open(flname, 'w')
	if not fd:
		return -1

	fd.write(p32(0x234)+'\n')
	for f in fdic:
		name = fdic[f].name
		addr = p64(int(fdic[f].address))
		size = p32(int(fdic[f].size))
		#print_funcs(fdic[f])
		if(len(name) > 31):
			print "Invalid name length. Function name must be less than 32 bytes."
		padd = 32 - len(name)
		name = name + '\x00'*padd	
		fd.write(name + addr + size + '\n')

	fd.close()
	return 0

def main():
	if(len(sys.argv) < 2):
		print "Usage: python load_funcs.py <elf filename>"
		exit(0)

	FP	= "./"+sys.argv[1]

	elf	= ELF(FP)
	if elf:
		print "Loading function info for: "+FP
		write_funcs(elf)

if __name__ == "__main__":
	main()
