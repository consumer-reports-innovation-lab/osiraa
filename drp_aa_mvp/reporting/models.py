from django.db import models

from covered_business.models import CoveredBusiness
from data_rights_request.models import DataRightsRequest, DataRightsStatus
from user_identity.models import IdentityUser


class ReportEntry(models.Model):
    GET_RIGHTS = 'get-rights'
    EXERCISE   = 'exercise'
    GET_STATUS = 'get_status'
    REQUEST_TYPE_CHOICES = [
        (GET_RIGHTS, 'get_rights'),
        (EXERCISE, 'excercise'),
        (GET_STATUS, 'get_status'),
    ]

    ACCESS    = 'access'
    DELETION  = 'deletion'
    REQUEST_ACTION_CHOICES = [
        (ACCESS, 'access'),
        (DELETION, 'deletion'),
    ]
    
    CCPA      = 'ccpa'
    VOLUNTARY = 'voluntary'
    REGIME_CHOICES = [
        (CCPA, 'ccpa'),
        (VOLUNTARY, 'voluntary'),
    ]

    # request type
    request_type        = models.CharField(max_length=10, blank=True, default='', 
                                            choices=REQUEST_TYPE_CHOICES)

    # user
    user_id             = models.ForeignKey(IdentityUser, on_delete=models.CASCADE)
    user_first_name     = models.CharField(max_length=63, blank=True, default='')
    user_last_name      = models.CharField(max_length=63, blank=True, default='')

    # covered_business
    covered_biz_id      = models.ForeignKey(CoveredBusiness, on_delete=models.CASCADE)
    covered_biz_name    = models.CharField(max_length=127, blank=True, default='')
    is_pip              = models.BooleanField(default=False)

    # action (for excercise only)
    request_action      = models.CharField(max_length=10, blank=True, default='', 
                                            choices=REQUEST_ACTION_CHOICES)
    covered_regime      = models.CharField(max_length=31, blank=True, default='',
                                            choices=REGIME_CHOICES)

    # request_response
    request_date_time   = models.DateTimeField(auto_now=True)
    request_url         = models.URLField(max_length=127, blank=True, default='')
    response_code       = models.IntegerField(blank=True, default='')
    response_payload    = models.CharField(max_length=2027, blank=True, default='')
    is_success          = models.BooleanField(default=False)

