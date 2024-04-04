from django.urls import path
from . import views


urlpatterns = [
    # path('', views.index, name='index'),
    path('v1/data-rights-request/', views.exercise, name='receive_request'),
    path('v1/data-rights-request/<str:request_id>', views.get_status, name='get_status'),
    path('v1/agent/<str:aa_id>', views.agent, name='agent_router_ugghhh'),
]
