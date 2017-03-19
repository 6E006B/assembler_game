from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.db import models
from jsonfield import JSONField


class Stage(models.Model):
    name = models.CharField(max_length=64, unique=True)
    difficulty = models.PositiveSmallIntegerField()

    def __str__(self):
        return '{}'.format(self.name)


class Task(models.Model):
    stage = models.ForeignKey(Stage, related_name='tasks')
    level = models.PositiveIntegerField()
    title = models.CharField(max_length=32)
    description = models.TextField()
    hint = models.TextField(default="", blank=True)
    initial_register_list = JSONField(default=None, blank=True, null=True)
    expected_register_list = JSONField()
    code_prefix = models.TextField(default="", blank=True, null=True)
    code_postfix = models.TextField(default="", blank=True, null=True)

    def __str__(self):
        return '({}) {}'.format(self.level, self.title)


class TaskSolution(models.Model):
    user = models.ForeignKey(User, related_name='task_solutions')
    task = models.ForeignKey(Task, related_name='task_solutions')
    code = models.TextField()
    solved = models.BooleanField(default=False)

    def __str__(self):
        return '{}@{}:{}'.format(self.user, self.task, self.solved)
