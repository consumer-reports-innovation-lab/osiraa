from django.contrib.postgres.fields import ArrayField
from django.db import models

from enum import Enum
from typing import List, Optional, Set, TypedDict

from django.forms import EmailField

#from pydantic import HttpUrl, UUID4, validator, root_validator
#from datarightsprotocol.models.base import BaseModel

from covered_business.models import CoveredBusiness
from user_identity.models import IdentityUser


OPT_OUT     = 'opt_out'
OPT_IN      = 'opt_in'
ACCESS      = 'access'
DELETION    = 'deletion'
ACCESS_CAT  = 'access_cat'
ACCESS_SPEC = 'access_spec'

ACTION_CHOICES = [
    (OPT_OUT, 'sale:opt-out'),
    (OPT_IN, 'sale:opt-in'),
    (ACCESS, 'access'),
    (DELETION, 'deletion'),
    (ACCESS_CAT , 'access:categories '),
    (ACCESS_SPEC , 'access:specific ')
]

CCPA        = 'ccpa'
VOLUNTARY   = 'voluntary'

REGIME_CHOICES = [
    (CCPA, 'ccpa'),
    (VOLUNTARY, 'voluntary'),
]

"""
class RequestMetaData():
    version     = "0.9.3"
"""

IN_PROGRESS     = 'in_progress'
OPEN            = 'open'
FULFILLED       = 'fulfilled'
REVOKED         = 'revoked'
DENIED          = 'denied'
EXPIRED         = 'expired'

STATUS_CHOICES = [
    (IN_PROGRESS, 'in_progress'),
    (OPEN, 'open'),
    (FULFILLED, 'fulfilled'),
    (REVOKED, 'revoked'),
    (DENIED , 'denied'),
    (EXPIRED , 'expired')
]

class RequestStatus(str, Enum):
    in_progress     = "in_progress"
    open            = "open"
    fulfilled       = "fulfilled"
    revoked         = "revoked"
    denied          = "denied"
    expired         = "expired"


NEED_VERIFICATION       = 'need_user_verification'
SUSPECTED_FRAUD         = 'suspected_fraud'
INSUF_VERIFICAION       = 'insufficient_verification'
NO_MATCH                = 'no_match'
CLAIM_NOT_COVERED       = 'claim_not_covered'
OUTSIDE_JURISDICTION    = 'outside_jurisdiction'
OTHER                   = 'other'
NONE                    = ''

REASON_CHOICES = [
    (NEED_VERIFICATION, 'need_user_verification'),
    (SUSPECTED_FRAUD, 'suspected_fraud'),
    (INSUF_VERIFICAION, 'insufficient_verification'),
    (NO_MATCH, 'no_match'),
    (CLAIM_NOT_COVERED , 'claim_not_covered'),
    (OUTSIDE_JURISDICTION , 'outside_jurisdiction'),
    (OTHER, 'other'),
    (NONE, ''),
]

class RequestReason(str, Enum):
    need_verification           = "need_user_verification"
    suspected_fraud             = "suspected_fraud"
    insufficient_verification   = "insuf_verification"
    no_match                    = "no_match"
    claim_not_covered           = "claim_not_covered"
    too_many_requests           = "too_many_requests"
    outside_jurisdiction        = "outside_jurisdiction"
    other                       = "other"
    none                        = ""
    
    
class StateReasons(TypedDict):
    status: RequestStatus
    reasons: List[RequestReason]

def valid_states() -> StateReasons: 
    return {
        RequestStatus.open: [RequestReason.none],
        RequestStatus.in_progress: [ RequestReason.none, RequestReason.need_verification ],
        RequestStatus.fulfilled: [ RequestReason.none ],
        RequestStatus.revoked: [ RequestReason.none ],
        RequestStatus.denied: [
            RequestReason.suspected_fraud,
            RequestReason.insufficient_verification,
            RequestReason.no_match,
            RequestReason.claim_not_covered,
            RequestReason.outside_jurisdiction,
            RequestReason.other,
        ],
        RequestStatus.expired: [ RequestReason.none ],
    }

def is_valid_state_reason(state: RequestStatus, reason: RequestReason):
    valid_reasons = valid_states().get(state, [])
    return reason in valid_reasons

"""
    @root_validator
    def no_results_for_unfulfilled(cls, values):
        if values.get('status') != RequestStatus.fulfilled:
            if values.get('results_url') != None:
                raise ValueError("cannot have results_url for unfulfilled request!")
        return values

    @root_validator
    def reason_valid_for_status(cls, values):
        status = values.get('status')
        reason = values.get('reason')
        if not is_valid_state_reason(status, reason):
            raise ValueError("reason not valid for state")
        return values
"""


# ----------------------------------------------------------------------------------------------- #

class IdentityPayload(models.Model):
    issuer                  = models.TextField(max_length=127, blank=True, default='')
    audience                = models.TextField(max_length=127, blank=True, default='')
    subject                 = models.TextField(max_length=127, blank=True, default='')
    name                    = models.TextField(max_length=127, blank=True, default='')
    email                   = models.EmailField(max_length=127, blank=True, default='')
    email_verified          = models.BooleanField(default=False)
    phone_number            = models.TextField(max_length=15, blank=True, default='')
    phone_number_verified   = models.BooleanField(default=False)
    address                 = models.EmailField(max_length=127, blank=True, default='')
    address_verified        = models.BooleanField(default=False)
    power_of_attorney       = models.EmailField(max_length=127, blank=True, default='')


class DataRightsRequest(models.Model):
    request_id          = models.TextField(max_length=255, blank=True, default='')
    #meta                = models.JSONField(default=RequestMetaData())
    relationships       = ArrayField(models.CharField(max_length=31),  default=list)
    status_callback     = models.URLField(max_length=1023, blank=True, default='')
    regime              = models.CharField(max_length=31, choices=REGIME_CHOICES, default=CCPA)
    right               = models.CharField(max_length=31, choices=ACTION_CHOICES, default=None)
    identity            = models.ForeignKey(IdentityPayload, null=True, on_delete=models.CASCADE)  

    def __str__(self):
        return f"{self.request_id} asking {self.exercise} for {self.identity}"


class DataRightsStatus(models.Model):
    request_id              = models.TextField(max_length=255, blank=True, default='')
    received_at             = models.DateTimeField(null=True)
    results_url             = models.URLField(max_length=255, blank=True, default='')
    expected_by             = models.DateTimeField(null=True)
    processing_details      = models.TextField(max_length=1023, null=True, blank=True, default='')
    status                  = models.TextField(max_length=31, blank=True, default='', choices=STATUS_CHOICES)
    reason                  = models.TextField(max_length=31, null=True, blank=True, default='', choices=REASON_CHOICES)
    user_verification_url   = models.URLField(max_length=127, null=True, blank=True, default='')

    def __str__(self):
        return f"{self.request_id} received_at {self.received_at} status {self.status}"
  
"""
- request 
  - action, jurisdiction
  - response - code, payload
  - request_id, timestamp, status, reason

- status request []
  - response - code, payload
  - request_id, timestamp, status, reason
"""


# ----------------------------------------------------------------------------------------------- #

class DrpRequestStatusPair(models.Model):
    request_ref     = models.ForeignKey(DataRightsRequest, null=True, on_delete=models.CASCADE)
    response_ref    = models.ForeignKey(DataRightsStatus, null=True, on_delete=models.CASCADE)
    

class DrpRequestTransaction(models.Model):
    user_ref        = models.ForeignKey(IdentityUser, null=True, on_delete=models.CASCADE)
    company_ref     = models.ForeignKey(CoveredBusiness, null=True, on_delete=models.CASCADE)
    request_id      = models.TextField(max_length=255, blank=True, default='')
    current_status  = models.TextField(max_length=31, blank=True, default='', choices=STATUS_CHOICES)
    expires_date    = models.DateTimeField(null=True)
    is_final        = models.BooleanField(default=False)

    #excer_request   = models.ForeignKey(DrpRequestStatusPair, related_name='excer_request', null=True, on_delete=models.CASCADE)
    #status_requests = models.ManyToManyField(DrpRequestStatusPair)
    #revoke_request  = models.ForeignKey(DrpRequestStatusPair, related_name='revoke_request', null=True, on_delete=models.CASCADE)

