
from keystone import KsError

from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, get_object_or_404
from django.views import View

from .models import Stage, Task, TaskSolution
from .task_executor import TaskExecutor


class LoginRequiredBaseView(LoginRequiredMixin, View):
    login_url = '/accounts/login/'
    redirect_field_name = 'next'


class StagesView(LoginRequiredBaseView):

    def get(self, request, *args, **kwargs):
        return self.render_stages(request)

    def post(self, request, *args, **kwargs):
        return self.render_stages(request)

    def render_stages(self, request):
        all_stages = Stage.objects.all().order_by('difficulty')
        stages_list = []
        for stage in all_stages:
            stages_list.append({
                'stage': stage,
                'tasks_number': stage.tasks.count(),
                'tasks_solved_number': TaskSolution.objects.filter(user=request.user, task__in=stage.tasks.all()).count(),
            })
        return render(request, 'stages.html', {'stages': stages_list})


class StageView(LoginRequiredBaseView):

    def get(self, request, name, *args, **kwargs):
        return self.render_stage(request, name)

    def post(self, request, name, *args, **kwargs):
        return self.render_stage(request, name)

    def render_stage(self, request, name):
        user = request.user
        stage = get_object_or_404(Stage, name=name)
        all_levels = Task.objects.filter(stage=stage).order_by('level')
        solved_levels = Task.objects.filter(
            stage=stage,
            task_solutions__in=TaskSolution.objects.filter(user=user, solved=True)
        )
        return render(request, 'levels.html', {'stage': stage, 'levels': all_levels, 'solved_levels': solved_levels})


class TaskView(LoginRequiredBaseView):

    def get(self, request, id, *args, **kwargs):
        assert request.user.is_authenticated
        task = get_object_or_404(Task, id=id)
        task_solution, _ = TaskSolution.objects.get_or_create(task=task, user=request.user)
        registers_list = self.get_test_case_list(task)
        return render(request, 'task_cards.html', {
            'task': task,
            'code': task_solution.code,
            'test_case_list': registers_list,
        })

    def post(self, request, id, *args, **kwargs):
        context = {}
        task = get_object_or_404(Task, id=id)
        context['task'] = task
        task_solution, _ = TaskSolution.objects.get_or_create(task=task, user=request.user)
        if 'code' in request.POST and request.POST['code']:
            code = request.POST['code'].replace("\r", "")
            context['code'] = code
            task_solution.code = code
            task_executor = TaskExecutor(task)
            try:
                task_executor.execute(code)
                context['register_values_list'] = task_executor.get_actual_registers()
                context['solved'] = task_executor.was_successful()
                if not task_solution.solved and context['solved']:
                    task_solution.solved = True
            except KsError as e:
                context['error'] = str(e)
            task_solution.save()
        else:
            context['code'] = task_solution.code
        context['test_case_list'] = self.get_test_case_list(task, context.get('register_values_list'))
        return render(request, 'task_cards.html', context)

    def get_test_case_list(self, task, actual_registers_list=None):
        """
        Get the correct format to render the registers in the template.
        :param task: the task for which to create the list for
        :param actual_registers_list: actual register values as calculated by unicorn if available
        :return: data structure in the following format:
                    List[ represents test cases
                        Dict[ represents the columns for a single test case
                            'success': Boolean,
                            'actual_registers_available': Boolean,
                            'register_names': List[ register_names ],
                            'registers': List[
                                Dict{ initial_registers },
                                Dict{ expected_registers },
                                Dict{ actual_registers } : iff actual_registers_list otherwise None
                            ]
                        }
                    ]
        """
        if actual_registers_list:
            assert len(actual_registers_list) == len(task.test_cases.all())
        test_case_list = []
        for index, test_case in enumerate(task.test_cases.all()):
            initial_registers = test_case.get_initial_registers()
            expected_registers = test_case.get_expected_registers()
            success = True
            register_names = self.get_register_names(task.stage.registers, initial_registers, expected_registers)
            stage_initial_registers = task.stage.registers.copy()
            actual_registers = None if not actual_registers_list else {}
            for register_name in register_names:
                initial_registers[register_name] = initial_registers.get(
                    register_name,
                    stage_initial_registers.get(register_name)
                )
                expected_registers[register_name] = expected_registers.get(register_name)
                if actual_registers is not None:
                    actual_registers[register_name] = actual_registers_list[index].get(register_name)
                    if success and expected_registers[register_name] is not None:
                        success = expected_registers[register_name] == actual_registers[register_name]
            registers = [
                initial_registers,
                expected_registers,
                actual_registers
            ]
            test_case = {
                'success': success,
                'register_names': register_names,
                'actual_registers_available': actual_registers_list is not None,
                'registers': registers,
            }
            test_case_list.append(test_case)
        return test_case_list

    def get_register_names(self, stage_registers, initial_registers, expected_registers):
        # first get the ones of the stage to preserve the initial order
        register_names = list(stage_registers.keys())
        for register in list(initial_registers.keys()) + list(expected_registers.keys()):
            if register not in register_names:
                register_names.append(register)
        return register_names
