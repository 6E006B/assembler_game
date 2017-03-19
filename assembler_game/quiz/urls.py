
from django.conf.urls import url

from .views import QuestionView

urlpatterns = [
    url('^question$', QuestionView.as_view(), name='question'),
]