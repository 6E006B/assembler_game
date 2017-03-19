
from django.conf.urls import url

from views import StagesView, StageView, TaskView

urlpatterns = [
    url(r'^$', StagesView.as_view(), name='stages'),
    url(r'^stage/(?P<name>.*)/$', StageView.as_view(), name='stage'),
    url('^task/(?P<id>.*)/$', TaskView.as_view(), name='task'),
]