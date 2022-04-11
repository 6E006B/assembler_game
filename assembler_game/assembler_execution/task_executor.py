
from .assembler_translator import AssemblerTranslator
from .x86_emulator import X86Emulator


class TaskExecutor(object):

    def __init__(self, task):
        self.task = task
        self.at = AssemblerTranslator()
        self.cpu = None
        self.actual_registers = []

    def execute(self, assembler):
        self.actual_registers = []
        # iterate over all test cases
        for test_case in self.task.test_cases.all():
            hidden_code_prefix = test_case.get_hidden_code_prefix()
            execution_offset = 0
            if hidden_code_prefix:
                execution_offset = len(self.at.assemble(hidden_code_prefix, addr=X86Emulator.CODE_BASE_ADDRESS))
            complete_assembler_code = "\n".join([
                hidden_code_prefix,
                self.task.code_prefix,
                assembler,
                self.task.code_postfix
            ]).strip()
            initial_registers = test_case.get_initial_registers()
            expected_registers = test_case.get_expected_registers()
            stack = test_case.get_stack()
            machine_code = self.at.assemble(complete_assembler_code, addr=X86Emulator.CODE_BASE_ADDRESS)
            print("code: '{}'".format(self.at.stringify_assembly(self.at.assemble(complete_assembler_code, addr=X86Emulator.CODE_BASE_ADDRESS))))
            self.cpu = X86Emulator(machine_code, initial_registers, stack=stack, execution_offset=execution_offset)
            self.cpu.execute()
            self.actual_registers.append(self.get_relevant_registers(initial_registers, expected_registers))

    def get_actual_registers(self):
        return self.actual_registers

    def get_relevant_registers(self, initial_registers, expected_registers):
        stage_register_keys = [] if not self.task.stage.registers else self.task.stage.registers.keys()
        relevant_registers_list = set(list(initial_registers.keys()) + list(expected_registers.keys()) + list(stage_register_keys))
        relevant_registers = {}
        for register in relevant_registers_list:
            relevant_registers[register] = self.cpu.get_register(register)
        return relevant_registers

    def was_successful(self):
        success = True
        for index, test_case in enumerate(self.task.test_cases.all()):
            for register, value in test_case.get_expected_registers().items():
                success = self.actual_registers[index][register] == value
                if not success:
                    return success
        return success
