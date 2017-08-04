from django.contrib import admin

from .models import Stage, Task, TaskSolution, TaskTestCase


class TaskTestCaseInline(admin.StackedInline):
    model = TaskTestCase
    extra = 0


class TaskAdmin(admin.ModelAdmin):
    inlines = [
        TaskTestCaseInline,
    ]


admin.site.register(Stage)
admin.site.register(Task, TaskAdmin)
admin.site.register(TaskSolution)
admin.site.register(TaskTestCase)
