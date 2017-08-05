from __future__ import unicode_literals

from collections import OrderedDict

from django.contrib.auth.models import User
from django.db import models
from jsonfield import JSONField


class Stage(models.Model):
    name = models.CharField(max_length=64, unique=True)
    difficulty = models.PositiveSmallIntegerField()
    registers = JSONField(
        default={},
        blank=True,
        load_kwargs={'object_pairs_hook': OrderedDict}
    )

    def __str__(self):
        return '{}'.format(self.name)


class Task(models.Model):
    stage = models.ForeignKey(Stage, related_name='tasks')
    level = models.PositiveIntegerField()
    title = models.CharField(max_length=32)
    description = models.TextField()
    hint = models.TextField(default="", blank=True)
    initial_registers_default = JSONField(default={}, blank=True, load_kwargs={'object_pairs_hook': OrderedDict})
    expected_registers_default = JSONField(default={}, blank=True, load_kwargs={'object_pairs_hook': OrderedDict})
    hidden_code_prefix_default = models.TextField(default="", blank=True, null=True)
    stack_default = JSONField(default=[], blank=True)
    code_prefix = models.TextField(default="", blank=True, null=True)
    code_postfix = models.TextField(default="", blank=True, null=True)

    def __str__(self):
        return '({}) {}'.format(self.level, self.title)


class TaskTestCase(models.Model):
    task = models.ForeignKey(Task, related_name='test_cases')
    use_initial_registers_default = models.BooleanField(default=False)
    initial_registers = JSONField(default={}, blank=True, load_kwargs={'object_pairs_hook': OrderedDict})
    use_expected_registers_default = models.BooleanField(default=False)
    expected_registers = JSONField(load_kwargs={'object_pairs_hook': OrderedDict})
    use_hidden_code_prefix_default = models.BooleanField(default=False)
    hidden_code_prefix = models.TextField(default="", blank=True, null=True)
    use_stack_default = models.BooleanField(default=False)
    stack = JSONField(default=[], blank=True)

    def get_initial_registers(self):
        initial_registers = self.initial_registers
        if self.use_initial_registers_default:
            initial_registers = self.task.initial_registers_default
        return initial_registers

    def get_expected_registers(self):
        expected_registers = self.expected_registers
        if self.use_expected_registers_default:
            expected_registers = self.task.expected_registers_default
        return expected_registers

    def get_hidden_code_prefix(self):
        hidden_code_prefix = self.hidden_code_prefix
        if self.use_hidden_code_prefix_default:
            hidden_code_prefix = self.task.hidden_code_prefix_default
        return hidden_code_prefix

    def get_stack(self):
        stack = self.stack
        if self.use_stack_default:
            stack = self.task.stack_default
        return stack

    def __str__(self):
        return "TC for '{}'".format(self.task)


class TaskSolution(models.Model):
    user = models.ForeignKey(User, related_name='task_solutions')
    task = models.ForeignKey(Task, related_name='task_solutions')
    code = models.TextField()
    solved = models.BooleanField(default=False)

    def __str__(self):
        return '{}@{}:{}'.format(self.user, self.task, self.solved)
