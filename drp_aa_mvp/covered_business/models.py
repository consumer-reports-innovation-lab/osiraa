from django.contrib.postgres.fields import ArrayField
from django.db import models
from enum import Enum
from typing import List, Optional, Set, TypedDict

#from data_rights_request.models import Action

#from libs.models import UUIDModel



class CoveredBusiness(models.Model):
    OPT_OUT     = 'opt_out'
    OPT_IN      = 'opt_in'
    ACCESS      = 'access'
    DELETION    = 'deletion'
    ACCESS_CAT  = 'access_cat'
    ACCESS_SPEC = 'access_spec'

    SUPPORTED_ACTION_CHOICES = [
        (OPT_OUT, 'sale:opt-out'),
        (OPT_IN, 'sale:opt-in'),
        (ACCESS, 'access'),
        (DELETION, 'deletion'),
        (ACCESS_CAT , 'access:categories '),
        (ACCESS_SPEC , 'access:specific ')
    ]

    name                  = models.CharField(max_length=63, blank=True, default='')
    brand_name            = models.CharField(max_length=63, blank=True, default='')
    cb_id                 = models.CharField(max_length=63, blank=True, default='')
    logo                  = models.ImageField('Logo Image', upload_to='company-logos', blank=True)
    logo_thumbnail        = models.ImageField(upload_to='company-logos/thumbnails', blank=True)
    subtitle_description  = models.TextField(blank=True)
    discovery_endpoint    = models.URLField(max_length=127, blank=True, default='')
    api_root_endpoint     = models.URLField(max_length=127, blank=True, default='')
    supported_actions     = ArrayField(models.CharField(max_length=31, choices=SUPPORTED_ACTION_CHOICES),  default=list)
    
    # todo: these are going away for 0.7
    api_secret            = models.CharField(max_length=127, blank=True, default='')
    auth_bearer_token     = models.CharField(max_length=4096, blank=True, default='')

    signing_key          = models.CharField(max_length=127, blank=True, default='')
    verify_key           = models.CharField(max_length=4096, blank=True, default='')


    #list_of_rights
    #user_business_relationship

    #request_email = models.EmailField(blank=True)
    #is_internal_email = models.BooleanField(default=False)
    #opt_out_details = models.TextField(blank=True)
    #delete_data_details = models.TextField(blank=True)
    #request_description = models.TextField(blank=True)

    def __str__(self):
        return self.name
