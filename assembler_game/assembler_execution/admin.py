from django.contrib import admin

from .models import Stage, Task, TaskSolution

admin.site.register(Stage)
admin.site.register(Task)
admin.site.register(TaskSolution)
