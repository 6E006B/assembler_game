from __future__ import unicode_literals

from django.db import models


class Question(models.Model):
    title = models.CharField(max_length=32)
    body = models.TextField()


class Answer(models.Model):
    question = models.ForeignKey('Question', on_delete=models.CASCADE)
    text = models.TextField()
    correct = models.BooleanField()


class Player(object):
    pass
