
from django.urls import include, path
from django.contrib import admin
from django.contrib.auth.views import LoginView

urlpatterns = [
    path('exec/', include('assembler_execution.urls')),
    path('quiz/', include('quiz.urls')),
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
]
