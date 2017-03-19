from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views import View

from models import Answer, Question


class QuestionView(LoginRequiredMixin, View):

    login_url = '/login/'
    redirect_field_name = 'next'

    def get(self, request, *args, **kwargs):
        assert request.user.is_authenticated
        question = None
        answers = Answer.objects.filter(question=question)
        return render(request, 'quiz/question.html', {'question': question, 'answers': answers})

    def post(self, request, *args, **kwargs):
        assert request.user.is_authenticated
        success = False
        return render(request, 'quiz/question.html', {'success': success})
