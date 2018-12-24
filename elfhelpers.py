#!/usr/bin/python
from capstone import *
from capstone.x86 import *
from capstone.x86_const import *
# from disas_helpers import *
from elftools.elf.structs import *
from elftools.elf.sections import *
from elftools.elf.elffile import *
from sys import argv

def replace_instruction_offset(code, offset, replacement):
	return code[:offset] + replacement + code[offset + len(replacement):]

def replace_instruction(code, i, replacement):
	return replace_instruction_offset(code, i.address, replacement)

# def code_inject(filename, old_code, new_code, offset, inject):
def code_inject(filename, injections, old_code = 0, new_code = 0):
	elf = ELFAll(filename)
	code = elf.allcode
	origsize = len(code)

	# Make a copy.
	orig = str(code)

	cs = Cs(CS_ARCH_X86, CS_MODE_64)
	cs.detail = True

	init_off = elf.elf.get_section_by_name(".text").header.sh_offset
	load_vaddr = 0 # get_exec_load(elf.elf).header.p_vaddr

	injections_add = 0

	allocations_diff = old_code - new_code

	print "Allocations Diff:", hex(allocations_diff)

	# Prepare a huge NOP Sled the size of the entire code
	nops = "\x90" * origsize

	# Create trampoline code. Assume the symbol ".init" is always first.
	fini_off = init_off + elf.elf.get_section_by_name(".text").header.sh_size

	# Get the PLT functions
	dynsym = elf.elf.get_section_by_name(".dynsym")
	pltsyms = [u""] + [dynsym.get_symbol(r.entry.r_info_sym).name for r in elf.elf.get_section_by_name(".rela.plt").iter_relocations()]
	pltfuncs = get_plt_functions(filename, elf.elf.get_section_by_name(".plt"), pltsyms)

	# Now, for each exported symbol, create a branch to the new version.
	symbols = filter(lambda x: fini_off >= x["off"] >= init_off and x["name"] != "", [{"name": s.name, "off": s.entry.st_value - load_vaddr} for s in elf.elf.get_section_by_name(".symtab").iter_symbols()])

	# Sort the list
	symbols = sorted(symbols + pltfuncs, key = lambda x: x["off"])
	symbols = sorted(symbols, key = lambda x: x["off"])
	print "Symbols:", len(symbols)

	for offset, inject in injections:
		# Add all previous injections to offset
		offset += injections_add

		injlen = len(inject)

		for i in cs.disasm(code, 0):
			if "rip" in i.op_str:
				if (i.address > offset) and (i.address + i.size + rip_offset(i) < offset):
					# code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff - injlen - rip_off_operand(i)["oplen"] + 1))
					code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff - injlen))
				elif (i.address < offset) and (i.address + i.size + rip_offset(i) >= offset):
					#code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff + injlen - rip_off_operand(i)["oplen"] + 1))
					code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff + injlen))
					print hex(rip_offset(i)), "->", hex(rip_offset(i) + allocations_diff + injlen)

				#if (i.address > offset):
				#	code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff - injlen - rip_off_operand(i)["oplen"] + 1))
				#elif (i.address < offset):
				#	code = replace_instruction(code, i, rip_repack(i, rip_offset(i) + allocations_diff + injlen * 2 - rip_off_operand(i)["oplen"] + 1))

			elif (X86_GRP_JUMP in i.groups or X86_GRP_CALL in i.groups and is_int(i.op_str)):
				# Was the branch supposed to target before injection?
				if (i.address >= offset) and (branch_dest(i) < offset):
					code = replace_instruction(code, i, repack_branch(i, branch_offset(i) - injlen))
				# Was the branch supposed to target after injection?
				elif (i.address < offset) and (branch_dest(i) >= offset):
					code = replace_instruction(code, i, repack_branch(i, branch_offset(i) + injlen))

		code = code[:offset] + inject + code[offset:] + "\xc3"

		j = 0
		for s in symbols:
			orig_jmp_off = s["off"] - init_off
			dest_jmp_off = 0

			print "Placing trampoline at:", hex(orig_jmp_off)

			if (orig_jmp_off >= offset):
				dest_jmp_off += injlen + injections_add

			# Create a relative JUMP instruction
			jmp_inst = "\xe9" + pack("I", dest_jmp_off)

			# Am I going to run over the next function?
			if (orig_jmp_off + len(jmp_inst) >= origsize) or (j + 1 < len(symbols) and symbols[j + 1]["off"] - s["off"] < len(jmp_inst)):
				# print hex(0x6d8 + orig_jmp_off)
				# Try going back a bit, find a suitable place not occupied by a branch yet
				for i in xrange(len(jmp_inst), 256):
					if nops[orig_jmp_off - i:orig_jmp_off - i + len(jmp_inst)] == "\x90" * len(jmp_inst):
						# Create a backward jump there
						trampoline = "\xeb" + chr(256 - i - 2)
						nops = replace_instruction_offset(nops, orig_jmp_off, trampoline)

						# Fix the instruction
						jmp_inst = "\xe9" + pack("I", dest_jmp_off + i)

						orig_jmp_off -= i

						break
			nops = replace_instruction_offset(nops, orig_jmp_off, jmp_inst)


			j += 1

		injections_add += len(inject)

	
	return {"fixed": code, "trampolines": nops, "injections" : [(offset, len(inject))], "elf": elf}

def offset_diff(offset, injections):
	offset_diff = 0
	for injection_off, injection_size in injections:
		if injection_off <= offset:
			offset_diff += injection_size

	return offset_diff

def size_diff(offset, size, injections):
	section_size_diff = 0

	for injection_off, injection_size in injections:
		if offset <= injection_off <= offset + size:
			section_size_diff += injection_size

	return section_size_diff

def get_exec_load(elf):
	for s in elf.iter_segments():
		if s.header.p_type == "PT_LOAD" and s.header.p_flags & 0x1 == 0x1:
			return s

def get_data_load(elf):
	for s in elf.iter_segments():
		if s.header.p_type == "PT_LOAD" and s.header.p_flags & 0x1 == 0x0:
			return s

def fix_elf(elf, injections, injected_code):
	s = ELFStructs(elfclass = 32)
	
	# Read the ELF in its entirery
	elf.stream.seek(0)
	elf_data = elf.stream.read()
	elf.stream.seek(0)

	new_elf = {}


	# Get the init section, as all offsets are relative to it.
	init_offset = elf.get_section_by_name(".init").header.sh_offset
	load_vaddr = get_exec_load(elf).header.p_vaddr
	data_vaddr = get_data_load(elf).header.p_vaddr
	
	injections = [(off + init_offset, size) for off, size in injections]

	# ELF header
	elfhdr = elf.header.copy()
	elfhdr.e_entry += offset_diff(elf.header.e_entry - load_vaddr, injections)
	elfhdr.e_shoff += offset_diff(elf.header.e_shoff, injections)
	elfhdr.e_phoff += offset_diff(elf.header.e_phoff, injections)

	new_elf[(0, s.Elf_Ehdr.sizeof())] =  s.Elf_Ehdr.build(elfhdr)

	ph_off_next = elf.header.e_phoff + offset_diff(elf.header.e_phoff, injections)

	for phdr in elf.iter_segments():
		proghdr = phdr.header.copy()

		proghdr.p_offset += offset_diff(phdr.header.p_offset, injections)


		proghdr.p_paddr += offset_diff(phdr.header.p_paddr - load_vaddr, injections)
		
		# REMEMBER: This makes NON -fPIE ELF files to not execute as-is.
		#		Therefore, when loading a process (only non-pie), make sure that the data PT_LOAD is loaded
		#		at the ORIGINAL OFFSET. It usually has some significant diff from the EXEC PT_LOAD
		#		so it's supposed to work well. Somehow GlibC refuses to load a binary if it has p_vaddr
		#		and p_offset that does not align. SAD.
		if load_vaddr == 0 or proghdr.p_vaddr < data_vaddr or proghdr.p_type != "PT_LOAD":
			proghdr.p_vaddr += offset_diff(phdr.header.p_vaddr - load_vaddr, injections)

		# Enlarge size only of X segments
		if phdr.header.p_flags & 0x1 == 0x1:
			proghdr.p_memsz += size_diff(phdr.header.p_vaddr - load_vaddr, phdr.header.p_memsz, injections)
			proghdr.p_filesz += size_diff(phdr.header.p_offset, phdr.header.p_filesz, injections)

		new_elf[(ph_off_next, s.Elf_Phdr.sizeof())] = s.Elf_Phdr.build(proghdr)

		ph_off_next += s.Elf_Phdr.sizeof()

	sh_off_next = elf.header.e_shoff + offset_diff(elf.header.e_shoff, injections)

	# Program Header Table
	for section in elf.iter_sections():
		print "%-20s at 0x%x" % (section.name, sh_off_next)
		section_base = section.header.sh_offset + offset_diff(section.header.sh_offset, injections)

		if section.header.sh_type == "SHT_NULL":
			sectionhdr = section.header
		else:
			sectionhdr = section.header.copy()
			sectionhdr.sh_offset += offset_diff(section.header.sh_offset, injections)

			if load_vaddr == 0 or sectionhdr.sh_addr < data_vaddr:
				sectionhdr.sh_addr += offset_diff(section.header.sh_addr - load_vaddr, injections)

			# Don't support enlarging section size other than X sections
			if section.header.sh_flags & 0x4 == 0x4:
				sectionhdr.sh_size += size_diff(section.header.sh_offset, section.header.sh_size, injections)

		new_elf[(sh_off_next, s.Elf_Shdr.sizeof())] = s.Elf_Shdr.build(sectionhdr)
		sh_off_next += s.Elf_Shdr.sizeof()


		# Per-section-type encoding
		if type(section) == SymbolTableSection:
			# This can be copied in its entirety to the new ELF. Instead, copy it one-by-one just for a case where some future alteration might be needed.
			idx = 0

			for symbol in section.iter_symbols():
				copysym = symbol.entry.copy()

				copysym.st_value += offset_diff(symbol.entry.st_value - load_vaddr, injections)

				new_elf[(section_base + idx * s.Elf_Sym.sizeof(), s.Elf_Sym.sizeof())] = s.Elf_Sym.build(copysym)

				idx += 1

		elif type(section) == StringTableSection:
			# Brutal copy of the general import part. Strings are just a dump of the content
			new_elf[(section_base, section.header.sh_size)] = elf_data[section.header.sh_offset : section.header.sh_offset + section.header.sh_size]

		elif type(section) == GNUVerSymSection:
			idx = 0
			for symbol in section.iter_symbols():
				copysym = symbol.entry.copy()

				new_elf[(section_base + idx * s.Elf_Versym.sizeof(), s.Elf_Versym.sizeof())] = s.Elf_Versym.build(copysym)

				idx += 1

		elif type(section) == GNUVerNeedSection:
			# Lets hope this just works with copying the section to the correct place
			new_elf[(section_base, section.header.sh_size)] = elf_data[section.header.sh_offset : section.header.sh_offset + section.header.sh_size]

		elif type(section) == RelocationSection:
			idx = 0

			for reloc in section.iter_relocations():
				relcopy = reloc.entry.copy()

				relcopy.r_offset += offset_diff(reloc.entry.r_offset - load_vaddr, injections)

				# print "r_offset:", hex(relcopy.r_offset), "r_info:", hex(relcopy.r_info), "r_info_type:", relcopy.r_info_type, "r_info_sym:", relcopy.r_info_sym
				# Add this as build() is looking for it
				setattr(relcopy, "r_addend", 0)

				new_elf[(section_base + idx * s.Elf_Rela.sizeof(), s.Elf_Rela.sizeof())] = s.Elf_Rela.build(relcopy)

				idx += 1

		elif type(section) == DynamicSection:
			idx = 0

			for tag in section.iter_tags():
				if tag.entry.d_ptr >= load_vaddr:
					copytag = tag.entry.copy()
					copytag.d_ptr += offset_diff(tag.entry.d_ptr - load_vaddr, injections)
					copytag.d_val = copytag.d_ptr
				else:
					copytag = tag.entry

				new_elf[(section_base + idx * s.Elf_Dyn.sizeof(), s.Elf_Dyn.sizeof())] = s.Elf_Dyn.build(copytag)

				idx += 1

		# Work only with X memory section
		elif type(section) == Section and section.header.sh_flags & 0x4 == 0x4:
			add_off = offset_diff(section.header.sh_offset, injections)
			add_size = size_diff(section.header.sh_offset, section.header.sh_size, injections)

			start_off = section.header.sh_offset + add_off - init_offset
			end_off = section.header.sh_offset + add_off - init_offset + section.header.sh_size + add_size

			# print "Section name:", section.name, "Start offset:", hex(init_offset + start_off), "End offset:", hex(init_offset + end_off)

			new_elf[(section_base, section.header.sh_size + add_size)] = injected_code[start_off : end_off]

		# Other types of sections, just copy it...
		elif type(section) == Section:
			new_elf[(section_base, section.header.sh_size)] = elf_data[section.header.sh_offset : section.header.sh_offset + section.header.sh_size]

		# Anything that does not have a type will fall back to just copying the content to the new version.
		elif section.header.sh_type != "SHT_NULL":
			# print "Adding untyped section %s" % section.name
			new_elf[(section_base, section.header.sh_size)] = elf_data[section.header.sh_offset : section.header.sh_offset + section.header.sh_size]

	sorted_mem = sorted(new_elf.keys(), key = lambda x: x[0] + x[1])

	# print [ (hex(x[0]), hex(x[0] + x[1])) for x in sorted_mem ]

	finalized = ""
	prevend = 0

	# Finished parsing file. Rewrite to new file.
	for part in sorted_mem:
		if prevend != part[0]:
			if part[0] > prevend:
				# Pad with zeroes
				# print "Padding %d" % (part[0] - prevend)
				finalized += "\x00" * (part[0] - prevend)
			else:
				print "Found an anomaly!!!"
		# prevend = part[0] + part[1]
		# if part[1] != len(new_elf[part]):
		#	print "Wrong size at: (%s, %s). %d instead of %d" % (hex(part[0]), hex(part[0] + part[1]), len(new_elf[part]), part[1])
		# else:
		#	print "Writing %s (%s) - %s" % (hex(part[0]), hex(len(finalized)), hex(part[0] + part[1]))

		finalized = finalized[:part[0]] + new_elf[part]
		
	print "Number of injections: %d" % len(injections)


	return finalized
	
def detect_rets(filename):
	elf = ELFAll(filename)

	rets = []

	print "Starts at: 0x%x" % elf.text_off

	for i in elf.text.iter_code:
		if i.mnemonic == "ret":
			rets.append(i.address - elf.text_off)

	return rets

if __name__ == "__main__":
	from elfall import *
	if len(argv) != 1 + 1:
		print "Usage: %s <Filename>" % argv[0]

		exit(0)
	filename = argv[1] # "./t.interp"

	# off = 389
	# off = 0x769 - 0x5f0
	# off = 0x400550 - 0x4003e0
	# size = 30
	# injections = [(0x769 - 0x5f0, "\x90" * 30), (0x790 - 0x5f0, "\x90" * 40), (0x7e6 - 0x5f0, "\x90" * 50)]
	injections = [ (off, "\x90" * 5) for off in detect_rets(filename) ]

	# injections = [(0x856 - 0x6a0, "\x90" * 30), (0x8aa - 0x6a0, "\x90" * 30)]

	res = code_inject(filename, injections)

	fix_elf(res["elf"], res["elf"].elf, [(off, len(inject)) for off, inject in injections], res["fixed"])
