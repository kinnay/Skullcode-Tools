
import struct
import sys


class Disassembler:
	def __init__(self):
		self.registers = [
			"rNull", "rHeap", "rParam", "rText", "rEntity", "rCode", "rCall",
			"rStatus", "E_INVALID", "rBody", "rSpine", "rFree", "rSeed", "rSig",
			"rVirt", "PC"
		]
		
		self.types = ["8", "16", "32", "64", "128", "flt", "dbl", "128"]
		
		self.conditions = ["al", "eq", "le_u", "lt_u", "ge_u", "gt_u", "ne", "le", "lt", "ge", "gt"]
	
		self.opcodes = {
			0: self.opcode_halt,
			1: self.opcode_err,
			2: self.opcode_wait,
			
			#No idea how this works
			3: self.opcode_finger,
			4: self.opcode_clrfing,
			5: self.opcode_enhance,
			7: self.opcode_lock,
			
			8: self.opcode_mode,
			9: self.opcode_mov,
			10: self.opcode_cmp,
			11: self.opcode_jump,
			13: self.opcode_add,
			14: self.opcode_sub,
			15: self.opcode_not,
			16: self.opcode_xor,
			17: self.opcode_and,
			18: self.opcode_or,
			19: self.opcode_shl,
			20: self.opcode_shrx,
			21: self.opcode_shr,
			22: self.opcode_rotl,
			23: self.opcode_rotr,
			24: self.opcode_ext,
			25: self.opcode_neg,
			26: self.opcode_mul,
			27: self.opcode_div,
			28: self.opcode_mod,
			29: self.opcode_udiv,
			30: self.opcode_umod,
			31: self.opcode_call,
			32: self.opcode_ret,
			41: self.opcode_time,
			42: self.opcode_dtime
		}
		
	def get_src(self, instr):
		if instr & 0x8000: #Immediate
			type = (instr >> 8) & 7
			if type == 0: return "0x%02X" %(instr >> 24)
			elif type == 1: return "0x%04X" %(self.fetch() & 0xFFFF)
			elif type == 2:
				register = instr >> 24
				if register == 0: return "0x%08X" %self.fetch()
				elif register < len(self.registers): return self.registers[register]
				else:
					return "E_INVALID"
			elif type == 3: return "0x%08X%08X" %reversed((self.fetch(), self.fetch()))
			elif type in [4, 7]: return "0x%08X%08X%08X%08X" %reversed((self.fetch(), self.fetch(), self.fetch(), self.fetch()))
			elif type == 5: return "%ff" %struct.unpack("f", struct.pack("I", self.fetch()))[0]
			elif type == 6: return "%f" %struct.unpack("d", struct.pack("Q", self.fetch() | (self.fetch() << 32)))[0]

		#Load from memory
		offset = instr >> 24
		param = "rParam+0x%X" %offset if offset else "rParam"
		if not instr & 0x800:
			register = (instr >> 12) & 7
			if register == 0: base = param
			elif register == 7: base = "[%s]" %param
			else:
				base = "%s+[%s]" %(self.registers[register], param)
			return "[%s]" %base
		return "[%s]" %param
		
	#For bit shifts
	def get_src_alt(self, instr):
		if instr & 0x8000:
			if instr & 0x700 == 0x500:
				return self.get_src(instr - 0x300)
			return "0x%02X" %(instr >> 24)
		return self.get_src(instr)
		
	def get_src_sym(self, instr):
		if instr & 0x8000:
			if instr & 0x700 == 0x200:
				if instr >> 24 == 0:
					addr = self.fetch()
					if addr in self.symbols:
						return self.symbols[addr]
					return "0x%08X" %addr
		return self.get_src(instr)
		
	def get_dst(self, instr):
		slot = (instr >> 16) & 0xFF
		param = "rParam+0x%X" %slot if slot else "rParam"
		if instr & 0x800:
			basereg = (instr >> 12) & 7
			if basereg == 0:
				#Special purpose register (supervisor only)
				return self.registers[slot]
			elif basereg == 7:
				base = "[%s]" %param
			else:
				base = "%s+[%s]" %(self.registers[basereg], param)
		else:
			base = param
		return "[%s]" %base
		
	def get_type(self, instr):
		return self.types[(instr >> 8) & 7]
		
	def opcode_mov(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "mov.%s %s = %s" %(type, dst, src)
		
	def opcode_not(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "not.%s %s = ~%s" %(type, dst, src)
		
	def opcode_and(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "and.%s %s &= %s" %(type, dst, src)
		
	def opcode_or(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "or.%s %s |= %s" %(type, dst, src)
		
	def opcode_xor(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "xor.%s %s ^= %s" %(type, dst, src)
		
	def opcode_ext(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "ext.%s %s = %s" %(type, dst, src)
		
	def opcode_neg(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "neg.%s %s = -%s" %(type, dst, src)
		
	def opcode_add(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "add.%s %s += %s" %(type, dst, src)
		
	def opcode_sub(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "sub.%s %s -= %s" %(type, dst, src)
		
	def opcode_mul(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "mul.%s %s *= %s" %(type, dst, src)
		
	def opcode_div(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "div.%s %s /= %s" %(type, dst, src)
		
	def opcode_mod(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "mod.%s %s %%= %s" %(type, dst, src)
		
	def opcode_udiv(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "udiv.%s %s /= %s" %(type, dst, src)
		
	def opcode_umod(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "umod.%s %s %%= %s" %(type, dst, src)
		
	def opcode_cmp(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "cmp.%s %s, %s" %(type, dst, src)
		
	def opcode_shl(self, instr):
		type = self.get_type(instr)
		src = self.get_src_alt(instr)
		dst = self.get_dst(instr)
		return "shl.%s %s <<= %s" %(type, dst, src)
		
	#Signed shift
	def opcode_shrx(self, instr):
		type = self.get_type(instr)
		src = self.get_src_alt(instr)
		dst = self.get_dst(instr)
		return "shrx.%s %s >>= %s" %(type, dst, src)
		
	#Unsigned shift
	def opcode_shr(self, instr):
		type = self.get_type(instr)
		src = self.get_src_alt(instr)
		dst = self.get_dst(instr)
		return "shr.%s %s >>>= %s" %(type, dst, src)
		
	def opcode_rotl(self, instr):
		type = self.get_type(instr)
		src = self.get_src_alt(instr)
		dst = self.get_dst(instr)
		return "rol.%s %s, %s" %(type, dst, src)
		
	def opcode_rotr(self, instr):
		type = self.get_type(instr)
		src = self.get_src_alt(instr)
		dst = self.get_dst(instr)
		return "ror.%s %s, %s" %(type, dst, src)
	
	def opcode_ext(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "ext.%s %s, %s" %(type, dst, src)
		
	def opcode_call(self, instr):
		src = self.get_src_sym(instr)
		frame_size = (instr >> 14) & 0x3FC
		return "call -> [0x%X] %s" %(frame_size, src)
		
	def opcode_ret(self, instr):
		return "ret\n"
		
	def opcode_jump(self, instr):
		src = self.get_src_sym(instr)
		code = (instr >> 18) & 0x3F
		if code < len(self.conditions):
			cond = self.conditions[code]
		else:
			cond = "E_INVALID"
		newline = "\n" if code == 0 else ""
		return "jmp.%s -> %s%s" %(cond, src, newline)
		
	def opcode_time(self, instr):
		return "time %s" %self.get_dst(instr)
		
	def opcode_dtime(self, instr):
		return "dtime %s" %self.get_dst(instr)
		
	def opcode_wait(self, instr):
		return "wait %s" %self.get_src(instr)
		
	def opcode_halt(self, instr):
		return "halt"
		
	def opcode_err(self, instr):
		return "err %s" %self.get_src(instr)
	
	def opcode_finger(self, instr):
		type = self.get_type(instr)
		src = self.get_src(instr)
		dst = self.get_dst(instr)
		return "finger.%s %s, %s" %(type, dst, src)
	
	def opcode_clrfing(self, instr):
		return "clrfing"
		
	def opcode_enhance(self, instr):
		type = self.get_type(instr)
		dst = self.get_dst(instr)
		return "enhance.%s %s" %(type, dst)
		
	def opcode_lock(self, instr):
		return "lock"
		
	def opcode_mode(self, instr):
		#Switch to supervisor or user mode
		return "mode %s" %self.get_src(instr)

	def disassemble(self, data, outfile, symbols):
		self.data = data
		self.outfile = outfile
		self.symbols = symbols
		
		self.write("") #Newline

		self.pc = 0
		while self.pc < len(data):
			addr = self.pc
			if addr in symbols:
				self.write("%s:" %symbols[addr])

			instr = self.fetch()
			opcode = instr & 0xFF
			if opcode in self.opcodes:
				self.write("%04X:%08X: %s" %(addr, instr, self.opcodes[opcode](instr)))
			else:
				self.write("%04X:%08X: invalid opcode %i" %(addr, instr, opcode))
			
	def fetch(self):
		value = struct.unpack_from("<I", self.data, self.pc)[0]
		self.pc += 4
		return value
		
	def write(self, line):
		if self.outfile:
			self.outfile.write(line + "\n")
		else:
			print(line)
			
			
class Config:
	def init(self, args):
		if len(args) < 2:
			self.print_usage()
			return False
			
		self.infile = args[1]
		self.outfile = None
		self.symfile = None
		for i in range(2, len(args) - 1, 2):
			option = args[i]
			value = args[i+1]
			if option == "-o":
				self.outfile = value
			elif option == "-s":
				self.symfile = value
			else:
				print("Unrecognized option: %s" %option)
				return False
				
		return True
		
	def print_usage(self):
		print("Usage: python disassemble.py <filename> [<options>]")
		print("Options:")
		print("\t-o <outfile>")
		print("\t-s <symfile>")


config = Config()
if config.init(sys.argv):
	with open(config.infile, "rb") as f:
		data = f.read()
	
	outfile = None
	if config.outfile:
		outfile = open(config.outfile, "w")

	symbols = {}
	if config.symfile:
		with open(config.symfile) as f:
			for line in f:
				line = line.strip().replace(" ", "")
				if line:
					addr, name = line.split(":")
					symbols[int(addr, 16)] = name
		
	dis = Disassembler()
	dis.disassemble(data, outfile, symbols)
		
	if outfile:
		outfile.close()
