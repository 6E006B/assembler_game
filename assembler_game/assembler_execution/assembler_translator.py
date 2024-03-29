
from capstone import *
from keystone import *


class AssemblerTranslator(object):

    def __init__(self):
        self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        self.assembler = Ks(KS_ARCH_X86, KS_MODE_32)

    def assemble(self, code: str, addr: int = 0) -> bytes:
        return bytes(self.assembler.asm(code, addr)[0])

    def disassemble(self, bytes: bytes, addr: int = 0):
        return self.disassembler.disasm(bytes, addr)

    def stringify_assembly(self, assembly: bytes):
        assembled_string = ""
        for instruction in assembly:
            assembled_string += "{:02x}".format(instruction)
        return assembled_string

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

    assembly = at.assemble(assembler_code, addr=0x1000000)
    print("{} => {}".format(assembler_code, at.stringify_assembly(assembly)))

    instructions = at.disassemble(machine_code)
    print("{} => {}".format(binascii.hexlify(machine_code), at.stringify_disassembly(instructions)))

    machine_code = '\x34\x61\x34\x61'
    instructions = at.disassemble(machine_code)
    print("{} => {}".format(binascii.hexlify(machine_code), at.stringify_disassembly(instructions)))

    machine_code = b"\xb8\xa4\x03\x00\x00\xc3\xe8\xf5\xff\xff\xff\x89\xc3"
    machine_code = b"\x8B\x0D\x00\x00\x00\x02"
    instructions = at.disassemble(machine_code, addr=0x1000000)
    print("{} => {}".format(binascii.hexlify(machine_code), at.stringify_disassembly(instructions)))
