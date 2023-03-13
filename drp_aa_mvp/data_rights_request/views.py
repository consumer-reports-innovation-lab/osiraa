import base64
import json
import re
from typing import Optional

import arrow
import jwt
import requests
import validators
from covered_business.models import CoveredBusiness
from django.core import serializers
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from reporting.views import (test_discovery_endpoint, test_excercise_endpoint,
                             test_status_endpoint)
from user_identity.models import IdentityUser

from .models import (DataRightsRequest, DataRightsStatus, DrpRequestStatusPair,
                     DrpRequestTransaction, IdentityPayload)

selected_covered_biz: Optional[CoveredBusiness] = None


def index(request):
    user_identities     = IdentityUser.objects.all()
    covered_businesses  = CoveredBusiness.objects.all()
    request_actions     = get_request_actions_form_display(selected_covered_biz)

    context = { 
        'user_identities':      user_identities, 
        'covered_businesses':   covered_businesses, 
        'selected_covered_biz': selected_covered_biz,
        'request_actions':      request_actions
    }

    return render(request, 'data_rights_request/index.html', context)


def select_covered_business(request):
    user_identities             = IdentityUser.objects.all()
    covered_businesses          = CoveredBusiness.objects.all()
    sel_covered_biz_id          = request.POST.get('covered_business')
    selected_covered_biz        = CoveredBusiness.objects.get(pk=sel_covered_biz_id)
    covered_biz_form_display    = get_covered_biz_form_display(covered_businesses, selected_covered_biz)
    request_actions             = get_request_actions_form_display(selected_covered_biz)

    context = { 
        'user_identities':      user_identities, 
        'covered_businesses':   covered_biz_form_display, 
        'selected_covered_biz': selected_covered_biz,
        'request_actions':      request_actions
    }

    return render(request, 'data_rights_request/index.html', context)


def send_request_discover_data_rights(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    request_url     = covered_biz.discovery_endpoint  # + ".well-known/data-rights.json"
    bearer_token    = covered_biz.auth_bearer_token or ""

    if (validators.url(request_url)):
        unauthed_response = get_well_known(request_url)
        response = get_well_known(request_url, bearer_token)
        set_covered_biz_well_known_params(covered_biz, response)
        discover_test_results = test_discovery_endpoint(request_url, {
            'unauthed': unauthed_response,
            'authed': response
        })

        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     discover_test_results,
        }

    else:  
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /discover, no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def send_request_excercise_rights(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    user_id_id      = request.POST.get('user_identity')
    user_identity   = IdentityUser.objects.get(pk=user_id_id)
    request_action  = request.POST.get('request_action')
    covered_regime  = request.POST.get('covered_regime')
    request_url     = covered_biz.api_root_endpoint + "/exercise"
    bearer_token    = covered_biz.auth_bearer_token

    # todo: a missing param in the request_json could cause trouble ...
    #print('**  send_request_excercise_rights(): request_action = ' + request_action)

    request_json    = create_excercise_request_json(user_identity, covered_biz, 
                                                    request_action, covered_regime)

    if (validators.url(request_url)):
        response = post_exercise_rights(request_url, bearer_token, request_json)

        try:
            json.loads(response.text)
        except ValueError as e:
            request_sent_context = { 
                'covered_biz':      covered_biz,
                'request_url':      request_url, 
                'response_code':    response.status_code,
                'response_payload': 'invalid json in response for /excecise',
                'test_results':     [],
            }

            return render(request, 'data_rights_request/request_sent.html', request_sent_context)

        response_json = response.json()

        if ('request_id' in response_json):
            data_rights_transaction: DrpRequestTransaction = create_drp_request_transaction(user_identity,  
                                                            covered_biz, request_json, response_json)
        
        excercise_test_results = test_excercise_endpoint(request_json, response)

        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url': request_url, 
            'response_code': response.status_code,
            'response_payload': response.text,
            'test_results': excercise_test_results 
        }

    else:
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /excecise , no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def send_request_get_status(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    user_id_id      = request.POST.get('user_identity')
    user_identity   = IdentityUser.objects.get(pk=user_id_id)
    request_url     = covered_biz.api_root_endpoint + "/status"
    bearer_token    = covered_biz.auth_bearer_token

    # todo: might not find a request id, handle this ...
    request_id      = get_request_id (covered_biz, user_identity)

    if (validators.url(request_url)):
        response = get_status(request_url, bearer_token, request_id)

        # todo: log request to DB, setup status ping ...

        status_test_results = test_status_endpoint(request_url, response)

        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url': response.request.url, 
            'response_code': response.status_code,
            'response_payload': response.text,
            'test_results': status_test_results 
        }

    else:
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /status , no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def send_request_revoke(request):
    user_id_id      = request.POST.get('user_identity')
    cov_biz_id      = request.POST.get('covered_business')
    user_identity   = IdentityUser.objects.get(pk=user_id_id)
    covered_biz     = CoveredBusiness.objects.get(pk=cov_biz_id)
    request_url     = covered_biz.api_root_endpoint + "/revoke"
    bearer_token    = covered_biz.auth_bearer_token
    request_id      = "pri_5e9f3775-549b-42ba-8d9f-c94a2e640f50"  #"c789ff35-7644-4ceb-9981-4b35c264aac3"
    reason          = "I don't want my account deleted."
    reqest_json     = create_revoke_request_json(request_id, reason)
    
    if (validators.url(request_url)):  
        response = post_revoke(request_url, bearer_token, reqest_json)

        # todo: log request to DB, stop status ping ...

        # todo: run DRP cerification tests ...
        
        context = { 
            'covered_biz':      covered_biz,
            'request_url':      response.request.url, 
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     [],
        }

    else:
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /revoke , no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def data_rights_request_sent_return(request):
    user_identities             = IdentityUser.objects.all()
    covered_businesses          = CoveredBusiness.objects.all()
    covered_biz_id              = request.POST.get('sel_covered_biz_id')
    selected_covered_biz        = CoveredBusiness.objects.get(pk=covered_biz_id)
    covered_biz_form_display    = get_covered_biz_form_display(covered_businesses, selected_covered_biz)
    request_actions             = get_request_actions_form_display(selected_covered_biz)

    context = { 
        'user_identities':      user_identities, 
        'covered_businesses':   covered_biz_form_display, 
        'selected_covered_biz': selected_covered_biz,
        'request_actions':      request_actions
    }

    return render(request, 'data_rights_request/index.html', context)


#-------------------------------------------------------------------------------------------------#

def set_covered_biz_well_known_params(covered_biz, response):

    # set api_root and supported_actions for covered_biz
    try:
        json.loads(response.text)
    except ValueError as e:
        print('**  WARNING - set_covered_biz_well_known_params(): NOT valid json  **')
        return False  
          
    try:
        reponse_json = response.json()
        covered_biz.api_root = reponse_json['api_base']
        covered_biz.supported_actions = reponse_json['actions']
        covered_biz.save()
    except KeyError as e:
        print('**  WARNING - set_covered_biz_well_known_params(): missing keys **')
        return False


def get_covered_biz_form_display(covered_businesses, selected_biz):
    if selected_biz == None:
        return covered_businesses

    covered_businesses_form_display = []

    for covered_biz in covered_businesses:
        covered_businesses_form_display.append({
            'id':       covered_biz.id,
            'name':     covered_biz.name,
            'selected': 'selected' if (covered_biz.id == selected_biz.id) else ''
        })

    return covered_businesses_form_display 
    
def covered_biz_has_supported_action(covered_biz, action):
    if action in covered_biz.supported_actions:
        return ''  # indicates NOT disabled

    return 'disabled'

def get_request_actions_form_display (covered_biz):
    if (covered_biz is None):  
        request_actions = [
            { 'action': 'sale:opt-out', 'label': 'Sale - Opt Out', 'disabled': 'disabled' },
            { 'action': 'sale:opt_in', 'label': 'Sale - Opt In', 'disabled': 'disabled' },
            { 'action': 'access', 'label': 'Access (View) User Data', 'disabled': '' },
            { 'action': 'deletion', 'label': 'Delete User Data', 'disabled': '' },
            { 'action': 'access:categories', 'label': 'Access User Data - Categories', 'disabled': 'disabled' },
            { 'action': 'access:specific', 'label': 'Access User Data - Specific', 'disabled': 'disabled' },
        ]

    else:
        request_actions = [
            { 'action': 'sale:opt-out', 'label': 'Sale - Opt Out', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'sale:opt-out') },
            { 'action': 'sale:opt_in', 'label': 'Sale - Opt In', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'sale:opt-in') },
            { 'action': 'access', 'label': 'Access (View) User Data', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'access') },
            { 'action': 'deletion', 'label': 'Delete User Data', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'deletion') },
            { 'action': 'access:categories', 'label': 'Access User Data - Categories', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'access:categories') },
            { 'action': 'access:specific', 'label': 'Access User Data - Specific', 
                'disabled': covered_biz_has_supported_action(covered_biz, 'access:specific') },
        ]

    return request_actions


def create_excercise_request_json(user_identity, covered_biz, request_action, covered_regime):
    jwt = create_jwt(user_identity, covered_biz)

    request_json = {
        "meta": { 
            "version": "0.5" 
        },
        "regime": covered_regime,
        "exercise": [
            request_action
        ],
        "relationships": [],
        "identity": jwt,
        "status_callback": "https://dsr-agent.example.com/update_status"
    }

    return request_json

def create_jwt(user_identity, covered_biz):
    jwt_algo        = "HS256"
    jwt_secret_enc  = covered_biz.api_secret
    if covered_biz.decode_api_secret == True:
      jwt_secret    = base64.b64decode(jwt_secret_enc)
    else:
      jwt_secret    = jwt_secret_enc
    id_payload      = create_id_payload(user_identity, covered_biz)

    return jwt.encode(
        id_payload,
        jwt_secret,
        jwt_algo
    )

def create_id_payload (user_identity, covered_biz):
    id_payload = {
        "iss": "https://consumerreports.com/",  # will match an entry in DB of trusted partners ...
        #"aud": covered_biz.name,               # skip for now, not yet supported on PIP side ...
        "sub": user_identity.email,             # identifier at the issuer, e.g. id of the user ...
        "name": (user_identity.last_name + ", " + user_identity.first_name),     
        "email": user_identity.email,      
        "phone_number": user_identity.phone_number,
        "address": user_identity.get_address(),
    }

    return id_payload


def create_revoke_request_json(request_id, reason):
    request_json = {
        "request_id": request_id,
        "reason": reason
    }

    return request_json


#-------------------------------------------------------------------------------------------------#

def create_drp_request_transaction(user_identity, covered_biz, reqest_json, response_json):

    identity_payload = IdentityPayload.objects.create(
        #issuer = 
        #audience = 
        #subject = 
        name                    = user_identity.first_name,         #user_identityfull_name,
        email                   = user_identity.email,
        email_verified          = user_identity.email_verified,
        phone_number            = user_identity.phone_number,
        phone_number_verified   = user_identity.phone_verified,
        address                 = user_identity.address1,           #user_identity.full_address,
        address_verified        = user_identity.address_verified,
        power_of_attorney       = user_identity.power_of_attorney,
    )

    data_rights_request = DataRightsRequest.objects.create(
        #request_id not sent on /excercise call
        #meta                    = reqest_json['meta'],
        relationships           = reqest_json['relationships'],
        status_callback         = reqest_json['status_callback'],
        regime                  = reqest_json['regime'],
        exercise                = reqest_json['exercise'],
        #identity                = reqest_json['identity'],
    )

    data_rights_status = DataRightsStatus.objects.create(
        # required fields
        request_id              = response_json['request_id'],
        status                  = response_json['status'],
        # optional/possible fields
        processing_details      = response_json.get('processing_details'),
        reason                  = response_json.get('reason'),
        user_verification_url   = response_json.get('user_verification_url'),
        # these fields need to be coerced to a datetime from arbitrary timestamps
        received_at             = enrich_date(response_json.get('received_at')),
        expected_by             = enrich_date(response_json.get('expected_by')),
    )

    #  todo: this doesn't seem to work ...
    #excercise_request = DrpRequestStatusPair.create(data_rights_request.id, data_rights_status.id)

    transaction = DrpRequestTransaction.objects.create(
        user_ref                = user_identity, 
        company_ref             = covered_biz,
        request_id              = data_rights_status.request_id,
        current_status          = data_rights_status.status,

        # todo: do expected_by and expires_date mean the same thing ... ?
        expires_date            = data_rights_status.expected_by,  

        is_final                = False,
        #excer_request           = excercise_request
    )

    return transaction


def enrich_date(dt: Optional[str]):
    '''
    arrow.get returns "now" if you pass it None -- we want to just not persist anything in that case.

    additionally, munge the input string to drop RFC3339 characters which are incorrectly parsed as timestamps
    '''
    if dt is None:
        return None
    if re.search(r'-[0-9]{4}$', dt):
        dt = dt[:-5] # sickos.jpg

    return arrow.get(dt).datetime


def get_request_id (covered_biz, user_identity):

    # todo: get the most recent one ...
    data_rights_transaction = DrpRequestTransaction.objects.filter(user_ref=user_identity.id).filter(company_ref=covered_biz.id)[0] #.latest()

    # todo: might not get a result, which could cause trouble down the line, so handle that situation ...

    request_id = data_rights_transaction.request_id

    return request_id



#-------------------------------------------------------------------------------------------------#

#GET /.well-known/data-rights.json
def get_well_known(discovery_url, bearer_token=""):
    if bearer_token != "":
        request_headers = {'Authorization': f"Bearer {bearer_token}"}
        response = requests.get(discovery_url, headers=request_headers)
    else:
        response = requests.get(discovery_url)

    """
    {
    "version": "0.5",
    "api_base": "https://example.com/data-rights",
    "actions": ["sale:opt-out", "sale:opt-in", "access", "deletion"],
    "user_relationships": [ ]
    }
    """

    return response


#POST /exercise
def post_exercise_rights(request_url, bearer_token, request_json):
    """
    curl -X 'POST' 
    'http://localhost:8080/api/v1/drp/excercise'
    -H 'accept: application/json'
    -H 'Authorization: Bearer eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Y2pZOkoc445kyqOZAKGjzw.-scnX7wxH2MeTohuCPPThCUFp7qUoyRA2hJlOsSUix6RmYRT2uz2sPUZnT-07-jYz3-32G07aIEyk30JeoHHsg3SMUa7V8Y2OlBI0WMaZ3QUscEuVZa7s3RuVVfvtePD195MMmH5w3RQkgxMrP8Lj8KubiYnRYw2n_rVt0crtP75s0NSnIF2ThWCAiq5gaGAdYSjzHwMWi9OAZekEuxNmFaTa2tu_j9Hi8uLbvjsp9-z5IjmGGsiTPNbPj5JgCWOxy-E-Ub6KMWMcCIxoLAki_Qfo5d1JwffvDQsEJT4zefm3HSdpFphv579KpgStLVhIh4r_5OnLl-w-ueHfDO3iCMgw8KIw7p5GtiXWggCejhJCohcM_g2msfG9OFeMd-7vLiFUuk4d4dzIbXXdOHGcv-lL3EyQUnRzQRXVGV3wHnxvN3Xyli4YQUqCk_qkJ1yf8LSJejqTklaCwovwuMWEu6ZwrXVq9OorMphHtnoRW-Ngw4oYa8SIME0YF3vdchCaglbNDhMVVjFkUkKsNBHfqUiZWLyXlNCluhQpMKORW5Uqk0mLtgLX_U5BlkibjcR9440UZvZoT_LBpiT21nLLtCdidHfW7bEgH9-bBMtoEwBeBM_RmxT1ysRKrdJ0NZCZgyU3FMijV-XFmIt2aZDaD2fnDJDBP1q0Aw1tVfucESZJHKUQtVKp6Q.EMaYOKnSqk2ApwP-uss3CA'
    """

    request_headers = {'Authorization': f"Bearer {bearer_token}"}

    response = requests.post(request_url, json=request_json, headers=request_headers)

    return response


# GET /status?request_id=c789ff35-7644-4ceb-9981-4b35c264aac3
def get_status(request_url, bearer_token, request_id):
    """
    curl -X 'GET' 
    'http://localhost:8080/api/v1/drp/status'
    -H 'accept: application/json'
    -H 'Authorization: Bearer eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Y2pZOkoc445kyqOZAKGjzw.-scnX7wxH2MeTohuCPPThCUFp7qUoyRA2hJlOsSUix6RmYRT2uz2sPUZnT-07-jYz3-32G07aIEyk30JeoHHsg3SMUa7V8Y2OlBI0WMaZ3QUscEuVZa7s3RuVVfvtePD195MMmH5w3RQkgxMrP8Lj8KubiYnRYw2n_rVt0crtP75s0NSnIF2ThWCAiq5gaGAdYSjzHwMWi9OAZekEuxNmFaTa2tu_j9Hi8uLbvjsp9-z5IjmGGsiTPNbPj5JgCWOxy-E-Ub6KMWMcCIxoLAki_Qfo5d1JwffvDQsEJT4zefm3HSdpFphv579KpgStLVhIh4r_5OnLl-w-ueHfDO3iCMgw8KIw7p5GtiXWggCejhJCohcM_g2msfG9OFeMd-7vLiFUuk4d4dzIbXXdOHGcv-lL3EyQUnRzQRXVGV3wHnxvN3Xyli4YQUqCk_qkJ1yf8LSJejqTklaCwovwuMWEu6ZwrXVq9OorMphHtnoRW-Ngw4oYa8SIME0YF3vdchCaglbNDhMVVjFkUkKsNBHfqUiZWLyXlNCluhQpMKORW5Uqk0mLtgLX_U5BlkibjcR9440UZvZoT_LBpiT21nLLtCdidHfW7bEgH9-bBMtoEwBeBM_RmxT1ysRKrdJ0NZCZgyU3FMijV-XFmIt2aZDaD2fnDJDBP1q0Aw1tVfucESZJHKUQtVKp6Q.EMaYOKnSqk2ApwP-uss3CA'
    """

    status_request_url = request_url + "?request_id=" + request_id
    request_headers = {'Authorization': f"Bearer {bearer_token}"}

    response = requests.get(status_request_url, headers=request_headers)

    return response



def post_revoke(request_url, bearer_token, request_json):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}

    response = requests.post(request_url, json=request_json, headers=request_headers)

    return response
