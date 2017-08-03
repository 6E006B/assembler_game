
from .assembler_translator import AssemblerTranslator
from .x86_emulator import X86Emulator


class TaskExecutor(object):

    def __init__(self, task):
        assert len(task.initial_register_list) == len(task.expected_register_list)
        self.task = task
        self.at = AssemblerTranslator()
        self.cpu = None
        self.actual_registers = []

    def execute(self, assembler):
        execution_offset = len(self.at.bytify_assembly(self.at.assemble(self.task.hidden_code_prefix, addr=X86Emulator.BASE_ADDRESS)))
        complete_assembler_code = "\n".join([
            self.task.code_prefix,
            assembler,
            self.task.code_postfix
        ]).strip()
        self.actual_registers = []
        for i in range(len(self.task.initial_register_list)):
            initial_registers = self.task.initial_register_list[i]
            machine_code = self.at.bytify_assembly(self.at.assemble(complete_assembler_code, addr=X86Emulator.BASE_ADDRESS))
            self.cpu = X86Emulator(machine_code, initial_registers, execution_offset=execution_offset)
            self.cpu.execute()
            self.actual_registers.append(self.get_relevant_registers(initial_registers, self.task.expected_register_list[i]))

    def get_actual_registers(self):
        return self.actual_registers

    def get_relevant_registers(self, initial_registers, expected_registers):
        stage_register_keys = [] if not self.task.stage.registers else self.task.stage.registers.keys()
        relevant_registers_list = set(initial_registers.keys() + expected_registers.keys() + stage_register_keys)
        relevant_registers = {}
        for register in relevant_registers_list:
            relevant_registers[register] = self.cpu.get_register(register)
        return relevant_registers

    def was_successful(self):
        success = True
        for i in range(len(self.task.expected_register_list)):
            for register, value in self.task.expected_register_list[i].items():
                success = self.actual_registers[i][register] == value
                if not success:
                    return success
        return success

    def was_successful_old(self):
        success = True
        for register, value in self.task.expected_register_list.items():
            success = self.cpu.get_register(register) == value
            if not success:
                break
        return success
