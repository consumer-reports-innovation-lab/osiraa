from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='index'),

    path('make_request', views.index, name='make_request'),

    path('select_covered_business', views.select_covered_business, name='select_covered_business'),

    path('setup_pairwise_key', views.setup_pairwise_key, name='setup_pairwise_key'),

    path('get_agent_information', views.get_agent_information, name='get_agent_information'),

    path('send_request_discover_data_rights', views.send_request_discover_data_rights, 
        name='send_request_discover_data_rights'),

    path('send_request_excercise_rights', views.send_request_excercise_rights, 
        name='send_request_excercise_rights'),

    path('send_request_get_status', views.send_request_get_status, 
        name='send_request_get_status'),

    path('send_request_revoke', views.send_request_revoke, name='send_request_revoke'),

    path('data_rights_request_sent_return', views.data_rights_request_sent_return, 
         name='data_rights_request_sent_return'),
]
