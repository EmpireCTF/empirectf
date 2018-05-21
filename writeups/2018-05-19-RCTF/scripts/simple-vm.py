#!/usr/bin/env python

def match(opcodes, opcode):
	assert opcodes[0] == opcode
	opcodes.pop(0)

def parse_uint32_l(opcodes):
	return hex(opcodes.pop(0) + \
		(opcodes.pop(0) << 8) + \
		(opcodes.pop(0) << 16) + \
		(opcodes.pop(0) << 24))

def return_vm(opcodes, ret_list):
	match(opcodes, 0)
	ret_list.append("return " + parse_uint32_l(opcodes))

def jmp_vm(opcodes, ret_list):
	match(opcodes, 1)
	ret_list.append("jmp " + parse_uint32_l(opcodes))

def assign_vm(opcodes, ret_list):
	match(opcodes, 2)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] = " + parse_uint32_l(opcodes))

def set_cond_vm(opcodes, ret_list):
	match(opcodes, 3)
	ret_list.append("cond = byte [" + parse_uint32_l(opcodes) + "]")

def get_cond_vm(opcodes, ret_list):
	match(opcodes, 4)
	ret_list.append("byte [" + parse_uint32_l(opcodes) + "] = (byte)cond")

def set_global_vm(opcodes, ret_list):
	match(opcodes, 5)
	ret_list.append("global = byte [" + parse_uint32_l(opcodes) + "]")

def get_global_vm(opcodes, ret_list):
	match(opcodes, 6)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] = global")

def cond_plus_global(opcodes, ret_list):
	match(opcodes, 7)
	ret_list.append("cond += global")

def some_logic_oper_vm(opcodes, ret_list):
	match(opcodes, 8)
	ret_list.append("cond = ~(global & cond)")

def get_char(opcodes, ret_list):
	match(opcodes, 0xa)
	ret_list.append("cond = getchar()")

def put_char(opcodes, ret_list):
	match(opcodes, 0xb)
	ret_list.append("putchar(cond)")

def cond_jmp(opcodes, ret_list):
	match(opcodes, 0xc)
	ret_list.append("[" + parse_uint32_l(opcodes) + "] ? jmp " + parse_uint32_l(opcodes) + " and --")

def cond_plus_1(opcodes, ret_list):
	match(opcodes, 0xd)
	ret_list.append("cond += 1")

def global_plus_1(opcodes, ret_list):
	match(opcodes, 0xe)
	ret_list.append("global += 1")

def cond_eq_global(opcodes, ret_list):
	match(opcodes, 0xf)
	ret_list.append("cond = global")

def global_eq_cond(opcodes, ret_list):
	match(opcodes, 0x10)
	ret_list.append("global = cond")

def plus(opcodes, ret_list):
	match(opcodes, 0x11)
	ret_list.append("cond += " + parse_uint32_l(opcodes))

def assign_reg_vm(opcodes, ret_list):
	match(opcodes, 0x12)
	ret_list.append("cond = byte [global]")

def assign_creg_vm(opcodes, ret_list):
	match(opcodes, 0x13)
	ret_list.append("cond = byte [cond]")

def asssign_cond(opcodes, ret_list):
	match(opcodes, 0x14)
	ret_list.append("cond = " + parse_uint32_l(opcodes))

def asssign_global(opcodes, ret_list):
	match(opcodes, 0x15)
	ret_list.append("global = " + parse_uint32_l(opcodes))

def gobal_ref_eq_cond(opcodes, ret_list):
	match(opcodes, 0x16)
	ret_list.append("[global] = cond")

def cond_minus_global(opcodes, ret_list):
	match(opcodes, 0x17)
	ret_list.append("cond -= global")

def cond_jmp_based_on_cond(opcodes, ret_list):
	match(opcodes, 0x18)
	ret_list.append("cond ? jmp " + parse_uint32_l(opcodes))

def nop(opcodes, ret_list):
	opcodes.pop(0)
	ret_list.append("nop")

opcode_dic = {
0 : return_vm,
1 : jmp_vm,
2 : assign_vm,
3 : set_cond_vm,
4 : get_cond_vm,
5 : set_global_vm,
6 : get_global_vm,
7 : cond_plus_global,
8 : some_logic_oper_vm,
0xa : get_char,
0xb : put_char,
0xc : cond_jmp,
0xd : cond_plus_1,
0xe : global_plus_1,
0xf : cond_eq_global,
0x10 : global_eq_cond,
0x11 : plus,
0x12 : assign_reg_vm,
0x13 : assign_creg_vm,
0x14 : asssign_cond,
0x15 : asssign_global,
0x16 : gobal_ref_eq_cond,
0x17 : cond_minus_global,
0x18 : cond_jmp_based_on_cond
}

def disassemble_vm(opcodes):
	total_len = len(opcodes)
	ret_list = []
	while len(opcodes) > 0:
		ret_list.append(hex(total_len - len(opcodes) + 0x30))
		if opcodes[0] in opcode_dic:
			opcode_dic[opcodes[0]](opcodes, ret_list)
		else:
			nop(opcodes, ret_list)
		print "\n".join(ret_list)
		print "\n\n"

with open('./p.bin', 'r') as content_file:
	content = content_file.read()

content = map(ord, list(content[0x30:0xe2]))

print content

disassemble_vm(content)
