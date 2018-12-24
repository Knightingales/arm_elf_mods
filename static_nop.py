#!/usr/bin/python
from elfhelpers import *
from sys import argv
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm import *

# get_section = lambda elf, section: filter(lambda x: x is not None, [x if x.name == section else None for x in elf.iter_sections()])[0]

def push_bin(elf, bin, offset):
	# Now, get all the code sections (usually starts with .init and ands in .fini)
	init = elf.get_section_by_name(".init")
	code_start_off = init.header.sh_offset
	
	# Get the end offset
	fini = elf.get_section_by_name(".fini")
	code_end_off = fini.header.sh_offset + fini.header.sh_size
	
	print ".init start:", code_start_off, "X size:", code_end_off - code_start_off

	# Set the file caret at beginning of code
	elf.stream.seek(code_start_off)

	# Read code
	code = elf.stream.read(code_end_off - code_start_off)

	# Get the .text section header as usually we'll inject there
	text = elf.get_section_by_name(".text")
		
	# Remember offset from init	
	off_from_init = text.header.sh_offset - init.header.sh_offset + offset

	# Inject the code
	code = code[:off_from_init] + "\x00\x00" + code[off_from_init:]
	
	new_elf = fix_elf(elf, [(off_from_init, 2)], code)

	return new_elf
	
if len(argv) != 1+ 2:
	print "%s <ARM ELF> <Offset>" % argv[0]
	exit(0)

with open(argv[1], 'rb') as f:
	data = push_bin(ELFFile(f), "\x00\x00", 22)
	# data = push_bin(ELFFile(f), "\x00\x00", int(argv[2]))

with open("%s.tampered" % argv[1], 'wb') as f:
	f.write(data)
