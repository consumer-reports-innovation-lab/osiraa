from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='index'),
    path('identity_verification.html', views.identity_verification, name='identity_verification'),
    path('refresh_service_directory_data', views.refresh_service_directory_data, name='refresh_service_directory_data'),
    path('select_covered_business', views.select_covered_business, name='select_covered_business'),
    path('setup_pairwise_key', views.setup_pairwise_key, name='setup_pairwise_key'),
    path('get_agent_information', views.get_agent_information, name='get_agent_information'),
    path('send_request_exercise_rights', views.send_request_exercise_rights, name='send_request_exercise_rights'),
    path('send_request_get_status', views.send_request_get_status, name='send_request_get_status'),
    path('send_request_revoke', views.send_request_revoke, name='send_request_revoke'),
    path('data_rights_request_sent_return', views.data_rights_request_sent_return, name='data_rights_request_sent_return'),
]
