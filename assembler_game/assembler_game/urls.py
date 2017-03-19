
from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.auth.views import login

urlpatterns = [
    url(r'^exec/', include('assembler_execution.urls')),
    url(r'^quiz/', include('quiz.urls')),
    url(r'^admin/', admin.site.urls),
    url(r'^login/?$', login, {'template_name': 'login.html'}, name='login'),
]
