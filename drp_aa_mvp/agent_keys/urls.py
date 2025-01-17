from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('generate_auth_agent_keys', views.generate_auth_agent_keys, name='generate_auth_agent_keys'),
    path('generate_auth_agent_keys_return', views.generate_auth_agent_keys_return, name='generate_auth_agent_keys_return'),
]