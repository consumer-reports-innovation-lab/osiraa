from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name='index'),

    path('make_request', views.index, name='make_request'),

    path('select_covered_business', views.select_covered_business, name='select_covered_business'),

    path('send_request_discover_data_rights', views.send_request_discover_data_rights, 
        name='send_request_discover_data_rights'),

    path('send_request_excercise_rights', views.send_request_excercise_rights, 
        name='send_request_excercise_rights'),

    path('send_request_get_status', views.send_request_get_status, 
        name='send_request_get_status'),

    path('send_request_revoke', views.send_request_revoke, name='send_request_revoke'),

    #path('request_sent', views.request_sent, name='request_sent'),

    path('data_rights_request_sent_return', views.data_rights_request_sent_return, 
         name='data_rights_request_sent_return'),

    path('setup_pairwise_key', views.setup_pairwise_key, name='setup_pairwise_key'),
]
