from pwn import *
import sys

def print_funcs(f):
	print "Name: "+f.name+"\tAddr: "+hex(f.address)+"\tSize: "+str(f.size)+"\n"
	return

def write_funcs(elf):
	flname	= "ftable.txt"
	fdic	= elf.functions
	#got	= elf.got
	plt	= elf.plt
	fd	= open(flname, 'w')
	if not fd:
		return -1

	fd.write(p32(0x234)+'\n')
	fd.write(p32(len(fdic))+'\n')
	for f in fdic:
		name = fdic[f].name
		addr = int(fdic[f].address)
		size = int(fdic[f].size)
		data = elf.read(addr, size)
		addr = p64(addr)
		size = p32(size)
		#print_funcs(fdic[f])
		#print data
		if(len(name) > 31):
			print "Invalid name length. Function name must be less than 32 bytes."
		padd = 32 - len(name)
		name = name + '\x00'*padd

		fd.write(name + addr + size + '\n')
		fd.write(data)
		fd.write('\n')

	fd.write(p32(0x567)+'\n')
	for p in plt:
		name = str(p)
		addr = p64(int(plt[p]))
		if(len(name) > 31):
			print "Invalid plt name length."
		padd = 32 - len(name)
		name = name + '\x00'*padd

		fd.write(name + addr + '\n')

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
