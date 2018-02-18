from pwn import *
import sys

def print_funcs(f):
	print "Name: "+f.name+"\tAddr: "+hex(f.address)+"\tSize: "+str(f.size)+"\n"
	return

def write_header(elf, fd):
	arc	= elf.arch
	txt	= elf.get_section_by_name('.text').header.sh_addr
	plt	= elf.get_section_by_name('.plt').header.sh_addr
	got	= elf.get_section_by_name('.got').header.sh_addr

	fd.write(p32(0x1001)+'\n')
	fd.write(arc+'\n')
	fd.write(p64(txt) + p64(plt) + p64(got))
	fd.write('\n')

	print "ELF Header Info:"
	print "Arch Type:\t\t"+arc
	print ".text:\t\t"+hex(txt)
	print ".plt:\t\t"+hex(plt)
	print ".got:\t\t"+hex(got)+'\n'

	return

def write_funcs(elf, fd):
	fdic	= elf.functions
	#got	= elf.got
	plt	= elf.plt

	fd.write(p32(0x234)+'\n')
	fd.write(p32(len(fdic))+'\n')
	print "symbols:"
	for f in fdic:
		name = fdic[f].name
		addr = int(fdic[f].address)
		size = int(fdic[f].size)
		data = elf.read(addr, size)
		addr = p64(addr)
		size = p32(size)
		print_funcs(fdic[f])
		#print data
		if(len(name) > 31):
			print "Invalid name length. Function name must be less than 32 bytes."
		padd = 32 - len(name)
		name = name + '\x00'*padd

		fd.write(name + addr + size + '\n')
		fd.write(data)
		fd.write('\n')

	fd.write(p32(0x567)+'\n')
	print "plt functions: "
	for p in plt:
		name = str(p)
		print name
		addr = p64(int(plt[p]))
		if(len(name) > 31):
			print "Invalid plt name length."
		padd = 32 - len(name)
		name = name + '\x00'*padd
	
		fd.write(name + addr + '\n')

	return 0

def main():
	filename	= "ftable.txt"
	if(len(sys.argv) < 2):
		print "Usage: python load_funcs.py <elf filename>"
		exit(0)

	FP	= "./"+sys.argv[1]

	elf	= ELF(FP)
	fd	= open(filename, 'w')
	if not elf:
		print "Error: bad ELF file"
		exit(1)
	if not fd:
		print "Error: failed to open file: "+filename
		exit(1)

	write_header(elf, fd)
	write_funcs(elf, fd)
	fd.close()

if __name__ == "__main__":
	main()
