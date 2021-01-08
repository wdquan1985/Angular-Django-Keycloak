"""django_keycloak URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/adminresource/', views.AdminView.as_view()),
    path('api/keycloak/token/', views.KeycloakTokenView.as_view()),
    path('api/keycloak/logout/', views.KeycloakLogoutView.as_view()),
    path('api/keycloak/config/', views.KeycloakConfigView.as_view()),
    path('api/automation/token/', views.AutomationTokenView.as_view())
]
