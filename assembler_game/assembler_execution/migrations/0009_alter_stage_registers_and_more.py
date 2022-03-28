# Generated by Django 4.0.3 on 2022-03-28 09:34

import collections
from django.db import migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('assembler_execution', '0008_auto_20190626_0032'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stage',
            name='registers',
            field=jsonfield.fields.JSONField(blank=True, default={}, load_kwargs={'object_pairs_hook': collections.OrderedDict}),
        ),
        migrations.AlterField(
            model_name='task',
            name='expected_registers_default',
            field=jsonfield.fields.JSONField(blank=True, default={}, load_kwargs={'object_pairs_hook': collections.OrderedDict}),
        ),
        migrations.AlterField(
            model_name='task',
            name='initial_registers_default',
            field=jsonfield.fields.JSONField(blank=True, default={}, load_kwargs={'object_pairs_hook': collections.OrderedDict}),
        ),
        migrations.AlterField(
            model_name='tasktestcase',
            name='expected_registers',
            field=jsonfield.fields.JSONField(load_kwargs={'object_pairs_hook': collections.OrderedDict}),
        ),
        migrations.AlterField(
            model_name='tasktestcase',
            name='initial_registers',
            field=jsonfield.fields.JSONField(blank=True, default={}, load_kwargs={'object_pairs_hook': collections.OrderedDict}),
        ),
    ]