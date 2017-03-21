from __future__ import print_function

import binascii
from unicorn import *
from unicorn.x86_const import *


class X86Emulator(object):

    REGISTERS = {
        'eax': UC_X86_REG_EAX,
        'ebx': UC_X86_REG_EBX,
        'ecx': UC_X86_REG_ECX,
        'edx': UC_X86_REG_EDX,
        'edi': UC_X86_REG_EDI,
        'ebp': UC_X86_REG_EBP,
        'eip': UC_X86_REG_EIP,
        'esi': UC_X86_REG_ESI,
        'esp': UC_X86_REG_ESP,
        'eflags': UC_X86_REG_EFLAGS,
        'ah': UC_X86_REG_AH,
        'al': UC_X86_REG_AL,
        'ax': UC_X86_REG_AX,
        'bh': UC_X86_REG_BH,
        'bl': UC_X86_REG_BL,
        'bx': UC_X86_REG_BX,
        'bp': UC_X86_REG_BP,
        'bpl': UC_X86_REG_BPL,
        'ch': UC_X86_REG_CH,
        'cl': UC_X86_REG_CL,
        'cx': UC_X86_REG_CX,
        'cs': UC_X86_REG_CS,
        'dh': UC_X86_REG_DH,
        'dl': UC_X86_REG_DL,
        'dx': UC_X86_REG_DX,
        'ds': UC_X86_REG_DS,
        'di': UC_X86_REG_DI,
        'dil': UC_X86_REG_DIL,
    }

    START_ADDRESS = 0x1000000

    def __init__(self, code, register_values):
        self.code = code
        self.cpu = Uc(UC_ARCH_X86, UC_MODE_32)
        self._initialise_memory()
        # self._initialise_registers()
        self.set_register_values(register_values)
        self.set_code(code)
        self.ip = self.START_ADDRESS

    def _initialise_memory(self):
        self.cpu.mem_map(self.START_ADDRESS, 2 * 1024 * 1024)

    def _initialise_registers(self):
        for register in self.REGISTERS.values():
            self.cpu.reg_write(register, 0x0)

    def set_register_values(self, register_values):
        for register, value in register_values.items():
            self.set_register(register, value)

    def set_code(self, code):
        self.code = code
        self.cpu.mem_write(self.START_ADDRESS, code)

    def get_register(self, register):
        return self.cpu.reg_read(self.REGISTERS[register])

    def set_register(self, register, value):
        self.cpu.reg_write(self.REGISTERS[register], value)

    def get_registers(self):
        registers_names = ['eax', 'ebx', 'ecx', 'edx', 'esp', 'eip', 'ebp', 'eflags']
        registers = {}
        for register in registers_names:
            registers[register] = self.get_register(register)
        return registers

    def execute(self):
        # emulate code in infinite time & unlimited instructions
        # print("executing '{}'".format(binascii.hexlify(self.code)))
        self.cpu.emu_start(self.START_ADDRESS, self.START_ADDRESS + len(self.code))

    def step(self):
        end_address = self.START_ADDRESS + len(self.code)
        if self.ip <= end_address:
            self.cpu.emu_start(self.ip, self.START_ADDRESS + len(self.code), count=1)
        old_ip = self.ip
        self.ip = self.get_register('eip')
        return end_address >= self.ip != old_ip

if __name__ == "__main__":
    # code to be emulated
    code = b"\x41\x4a" # INC ecx; DEC edx

    print("Emulate i386 code: '0x{}'".format(binascii.hexlify(code)))
    registers = {
        'ecx': 0x1234,
        'edx': 0x7890,
    }

    emu = X86Emulator(code, registers)
    # emu.execute()

    while emu.step():
        print('step()')
        registers = emu.get_registers()
        for reg, val in registers.items():
            print("{}: {}".format(reg, hex(val)))

    r_ecx = emu.get_register('ecx')
    r_edx = emu.get_register('edx')
    print(">>> ECX = 0x%x" % r_ecx)
    print(">>> EDX = 0x%x" % r_edx)
