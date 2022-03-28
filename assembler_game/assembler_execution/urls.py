
from django.urls import path

from .views import StagesView, StageView, TaskView

urlpatterns = [
    path('', StagesView.as_view(), name='stages'),
    path('stage/<name>/', StageView.as_view(), name='stage'),
    path('task/<id>/', TaskView.as_view(), name='task'),
]
