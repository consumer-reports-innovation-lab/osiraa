from django.urls import path
from . import views


urlpatterns = [
    # path('', views.index, name='index'),

    path('v1/data-rights-request/', views.validate_pynacl, name='receive_request'),
    path('v1/data-rights-request/<str:id>', views.request_handler, name='request_handler'),
    path('v1/agent/<str:id>', views.register_agent, name='register_agent'),
    path('v1/agent/', views.agent_status, name='agent_status'),
    # path('/v1/data-rights-request/', validate_pynacl, name='validate_pynacl'),
]
