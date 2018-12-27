#!/usr/bin/python
from sys import argv
from elftools.elf.elffile import ELFFile

def push_bin(elf, binstr, offset):
	# Get text information
	text = elf.get_section_by_name(".text")

	# Initialize read
	elf.stream.seek(0)

	# Get the entire code
	code = elf.stream.read()

	# Reset
	elf.stream.seek(0)

	# Inject binary
	return code[:text.header.sh_offset + offset] + binstr + code[text.header.sh_offset + offset:]
	
if len(argv) != 1+ 2:
	print "%s <ARM ELF> <Offset>" % argv[0]
	exit(0)

with open(argv[1], 'rb') as f:
	data = push_bin(ELFFile(f), "\x00\x00", 22)
	# data = push_bin(ELFFile(f), "\x00\x00", int(argv[2]))

with open("%s.tampered" % argv[1], 'wb') as f:
	f.write(data)
