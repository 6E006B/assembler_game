
from capstone import *
from keystone import *


class AssemblerTranslator(object):

    def __init__(self):
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self.assembler = Ks(KS_ARCH_X86, KS_MODE_32)

    def assemble(self, code, addr=0):
        return self.assembler.asm(code, addr)[0]

    def disassemble(self, bytes, addr=0):
        return self.disassembler.disasm(bytes, addr)

    def stringify_assembly(self, assembly):
        assembled_string = ""
        for instruction in assembly:
            assembled_string += "{:02x}".format(instruction)
        return assembled_string

    def bytify_assembly(self, assembly):
        byte_string = ''
        for instruction in assembly:
            byte_string += chr(instruction)
        return byte_string

    def stringify_disassembly(self, disassembly):
        assembler_string = ""
        for instruction in disassembly:
            assembler_string += "{} {}\n".format(instruction.mnemonic, instruction.op_str)
        return assembler_string.strip()


if __name__ == "__main__":
    import binascii
    at = AssemblerTranslator()
    assembler_code = "INC ecx;DEC edx"
    machine_code = b'\x41\x4a'

    assembly = at.assemble(assembler_code)
    print("{} => {}".format(assembler_code, at.stringify_assembly(assembly)))

    instructions = at.disassemble(machine_code)
    print("{} => {}".format(binascii.hexlify(machine_code), at.stringify_disassembly(instructions)))

    machine_code = '\x34\x61\x34\x61'
    instructions = at.disassemble(machine_code)
    print("{} => {}".format(binascii.hexlify(machine_code), at.stringify_disassembly(instructions)))
