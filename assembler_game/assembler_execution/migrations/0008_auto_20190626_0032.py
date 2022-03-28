# -*- coding: utf-8 -*-
# Generated by Django 1.10.6 on 2019-06-26 00:32
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('assembler_execution', '0007_auto_20170330_1429'),
    ]

    operations = [
        migrations.CreateModel(
            name='TaskTestCase',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('use_initial_registers_default', models.BooleanField(default=False)),
                ('initial_registers', jsonfield.fields.JSONField(blank=True, default={})),
                ('use_expected_registers_default', models.BooleanField(default=False)),
                ('expected_registers', jsonfield.fields.JSONField()),
                ('use_hidden_code_prefix_default', models.BooleanField(default=False)),
                ('hidden_code_prefix', models.TextField(blank=True, default='', null=True)),
                ('use_stack_default', models.BooleanField(default=False)),
                ('stack', jsonfield.fields.JSONField(blank=True, default=[])),
            ],
        ),
        migrations.RemoveField(
            model_name='task',
            name='expected_register_list',
        ),
        migrations.RemoveField(
            model_name='task',
            name='initial_register_list',
        ),
        migrations.AddField(
            model_name='task',
            name='expected_registers_default',
            field=jsonfield.fields.JSONField(blank=True, default={}),
        ),
        migrations.AddField(
            model_name='task',
            name='hidden_code_prefix_default',
            field=models.TextField(blank=True, default='', null=True),
        ),
        migrations.AddField(
            model_name='task',
            name='initial_registers_default',
            field=jsonfield.fields.JSONField(blank=True, default={}),
        ),
        migrations.AddField(
            model_name='task',
            name='stack_default',
            field=jsonfield.fields.JSONField(blank=True, default=[]),
        ),
        migrations.AddField(
            model_name='tasktestcase',
            name='task',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='test_cases', to='assembler_execution.Task'),
        ),
    ]
