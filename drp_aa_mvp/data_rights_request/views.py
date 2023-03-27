from datetime import datetime
from typing import Tuple
from django.core import serializers
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render

import requests
import json

from nacl import signing
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

import os
import validators

from .models import DataRightsRequest, DataRightsStatus, DrpRequestStatusPair, DrpRequestTransaction, IdentityPayload
from user_identity.models import IdentityUser
from covered_business.models import CoveredBusiness
from reporting.views import test_discovery_endpoint, test_pairwise_key_setup_endpoint, test_agent_information_endpoint, test_excercise_endpoint, test_status_endpoint, test_revoked_endpoint



#root_utl = os.environ['REQUEST_URI']
#print (f"****  root_url = {root_utl}")

auth_agent_drp_id       = 'CR_AA_DRP_ID_001'
auth_agent_callback_url = "http://127.0.0.1:8001/update_status" #f"{os.environ.get('SERVER_NAME')}/update_status" 

selected_covered_biz: CoveredBusiness = None


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


def setup_pairwise_key(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    request_url     = covered_biz.api_root_endpoint + f"/v1/agent/{auth_agent_drp_id}"
    request_json    = create_setup_pairwise_key_request_json(covered_biz_id)

    #  the only time we make new keys is when we call this setup method ...
    signing_key, verify_key = generate_keys()

    # Get the public key and signing key as b64 strings
    signing_key_b64 = signing_key.encode(encoder=Base64Encoder)
    verify_key_b64 = verify_key.encode(encoder=Base64Encoder)

    signed_request  = sign_request(signing_key, request_json)

    if (validators.url(request_url)):
        response = post_agent(request_url, signed_request)
        excercise_test_results = test_pairwise_key_setup_endpoint(request_json, response)
        set_covered_biz_pairwise_key_params(covered_biz, response, signing_key, verify_key)

        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     excercise_test_results,
        }

    else:  
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /create_pairwise_key, no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)



def get_agent_information(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    request_url     = covered_biz.api_root_endpoint + f"/v1/agent/{auth_agent_drp_id}"
    bearer_token    = covered_biz.auth_bearer_token or ""   

    if (validators.url(request_url)):
        response = get_agent(request_url, bearer_token)
        excercise_test_results = test_agent_information_endpoint(request_url, response)
        set_agent_info_params(covered_biz, response)

        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     excercise_test_results,
        }

    else:  
        request_sent_context = { 
            'covered_biz':      covered_biz,
            'request_url':      request_url, 
            'response_code':    'invalid url for /create_pairwise_key, no response',
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

    request_url     = covered_biz.api_root_endpoint + "/v1/data-right-request/"
    bearer_token    = covered_biz.auth_bearer_token

    # todo: a missing param in the request_jwt could cause trouble ...
    #print('**  send_request_excercise_rights(): request_action = ' + request_action)

    request_json    = create_excercise_request_json(user_identity, covered_biz, 
                                                    request_action, covered_regime)
    
    signed_request  = sign_request(covered_biz.signing_key, request_json)

    if (validators.url(request_url)):
        response = post_exercise_rights(request_url, bearer_token, signed_request)

        try:
            json.loads(response.text)
        except ValueError as e:
            request_sent_context = { 
                'covered_biz':      covered_biz,
                'request_url':      request_url, 
                'response_code':    response.status_code,
                'response_payload': 'invalid json in response for /v1/data-right-request/',
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
            'request_url':      request_url, 
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     excercise_test_results 
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
    request_url     = covered_biz.api_root_endpoint + "/v1/data-rights-request/"

    # todo: might not find a request id, need to handle this case ...
    request_id      = get_request_id (covered_biz, user_identity)

    if (validators.url(request_url)):
        # Data Rights Status requests SHALL be made without Authorization headers
        response = get_status(request_url, request_id)

        # todo: log request to DB, setup status callback ...

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
    #user_identity   = IdentityUser.objects.get(pk=user_id_id)
    covered_biz     = CoveredBusiness.objects.get(pk=cov_biz_id)

    bearer_token    = covered_biz.auth_bearer_token
    request_id      = "pri_5e9f3775-549b-42ba-8d9f-c94a2e640f50"  #"c789ff35-7644-4ceb-9981-4b35c264aac3"
    reason          = "I don't want my account deleted."

    request_url     =  "/v1/data-rights-request/" + request_id
    request_json    = create_revoke_request_json(reason)
    signed_request  = sign_request(covered_biz.signing_key, request_json)

    if (validators.url(request_url)):  
        response = post_revoke(request_url, bearer_token, signed_request)

        # todo: log request to DB, stop status ping ...

        test_revoked_endpoint(request_url, response)
        
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


#--------------------------------------------------------------------------------------------------#

def create_setup_pairwise_key_request_json(covered_biz_id):
    issued_time     = datetime.datetime.now()
    expires_time    = issued_time + datetime.timedelta(minutes=15)

    request_json = {
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz_id,
        "expires-at":   expires_time,
        "issued-at":    issued_time,
    }

    return request_json


def set_covered_biz_pairwise_key_params(covered_biz, response, signing_key, verify_key):
    try:
        json.loads(response.text)
    except ValueError as e:
        print('**  WARNING - set_covered_biz_pairwise_key_params(): NOT valid json  **')
        return False  
          
    try:
        response_json = response.json()

        """
        {
            "agent-id": "presented-agent-id",
            "token": "<str>"
        }
        """

        if not('agent' in response_json) or (response_json['agent'] != auth_agent_drp_id):
            return False

        if not('token' in response_json) or (response_json['token'] == ''):
            return False

        # todo: write signing_key & verify_key to CB ... ?

        covered_biz.auth_bearer_token = response_json['token']
        covered_biz.save()

    except KeyError as e:
        print('**  WARNING - set_covered_biz_pairwise_key_params(): missing keys **')
        return False
    

def create_agent_key_setup_json(agent_id, business_id):
    issued_time     = datetime.datetime.now()
    expires_time    = issued_time + datetime.timedelta(min=15)  # 15 minutes from now
   
    agent_key_setup_json = {
        "agent-id": agent_id,
        "business-id": business_id,
        "expires-at": expires_time,  
        "issued-at": issued_time
    }
     
    return agent_key_setup_json
   

def set_agent_info_params(response):
    try:
        json.loads(response.text)
    except ValueError as e:
        print('**  WARNING - set_agent_info_params(): NOT valid json  **')
        return False  
            
    try:
        reponse_json = response.json()

        # todo: should be empty json "{ }"

    except KeyError as e:
        print('**  WARNING - set_agent_info_params(): missing keys **')
        return False


#--------------------------------------------------------------------------------------------------#

def generate_keys() -> Tuple[str, str]:
    '''
    Returns tuple with signing and verify key
    '''
    # Generate a private key and a signing key
    # these are `bytes' objects
    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    return (signing_key, verify_key)


def sign_request(signing_key, request_json):
    signed_obj = signing_key.sign(json.dumps(request_json).encode())

    return signed_obj


"""
def submit_signed_request(validator_url):
    signing_key, verify_key = generate_keys()

    # Get the public key and signing key as b64 strings
    signing_key_b64 = signing_key.encode(encoder=Base64Encoder)
    verify_key_b64 = verify_key.encode(encoder=Base64Encoder)

    # Print the signing key
    print(f"Signing key: {signing_key_b64}")
    print(f"Verify key: {verify_key_b64}")

    signed_obj = make_req(signing_key)

    # Submit the signed object to the /validate endpoint
    request = Request(validator_url, signed_obj)
    request.add_header("content-type", "application/octet-stream")

    # smuggle DRP verify key in-band. This is NOT sufficient for production security!
    request.add_header("X-DRP-VerifyKey", verify_key_b64)

    try:
        response = urlopen(request)
    except urllib.error.HTTPError as e:
        resp = e.read()
    else:
        resp = response.read().decode()

    return resp
"""

"""
def create_jwt(user_identity, covered_biz):
    jwt_algo    = "HS256"
    jwt_secret  = covered_biz.api_secret
    id_payload  = create_id_payload(user_identity, covered_biz)

    return jwt.encode(
        id_payload,
        jwt_secret,
        jwt_algo
    )
"""


#--------------------------------------------------------------------------------------------------#

def create_excercise_request_json(user_identity, covered_biz, request_action, covered_regime):
    issued_time     = datetime.datetime.now()
    expires_time    = issued_time + datetime.timedelta(days=45)

    # 0.7 A Data Rights Exercise request SHALL contain a JSON-encoded message body containing the following fields, 
    #   with a libsodium/NaCl/ED25119 binary signature immediately prepended to it:
    request_json = {
        # 1
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz.cb_id,
        "expires-at":   expires_time,
        "issued-at":    issued_time,

        # 2
        "drp.version": "0.7",
        "exercise": request_action,
        "regime": covered_regime,
        "relationships": [ ],
        # callback url for the AA that the CB can hit to provide status updates, NYI
        "status_callback": auth_agent_callback_url,           
        
        # 3
        # claims in IANA JSON Web Token Claims page
        # see https://www.iana.org/assignments/jwt/jwt.xhtml#claims for details
        "name": (user_identity.last_name + ", " + user_identity.first_name),     
        "email": user_identity.email,      
        "phone_number": user_identity.phone_number,
        "address": user_identity.address1,
    }

    return request_json


def create_revoke_request_json(reason):
    request_json = {
        "reason": reason
    }

    return request_json


#-------------------------------------------------------------------------------------------------#

def create_drp_request_transaction(user_identity, covered_biz, request_json, response_json):
    identity_payload = IdentityPayload.objects.create(
        issuer                  = request_json.iss,       
        audience                = request_json.aud,
        expires_time            = request_json.exp,
        issued_time             = request_json.iat,
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
        #meta                    = request_json['meta'],
        relationships           = request_json['relationships'],
        status_callback         = request_json['status_callback'],
        regime                  = request_json['regime'],
        exercise                = request_json['exercise'],
        #identity                = request_json['identity'],
    )

    data_rights_status = DataRightsStatus.objects.create(
        request_id              = response_json['request_id'],
        received_at             = response_json['received_at'],
        expected_by             = response_json['expected_by'],
        processing_details      = response_json['processing_details'],
        status                  = response_json['status'],
        reason                  = response_json['reason'],
        user_verification_url   = response_json['user_verification_url'],
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
      "version": "0.7",
      "api_base": "https://example.com/data-rights",
      "actions": ["sale:opt-out", "sale:opt-in", "access", "deletion"],
      "user_relationships": [ ]
    }
    """

    return response


#POST /v1/data-right-request/ 
def post_exercise_rights(request_url, bearer_token, request_json):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.post(request_url, headers=request_headers, json=request_json)

    return response


# GET /v1/data-rights-request/{request_id}
def get_status(request_url, request_id):
    status_request_url = request_url + request_id
    response = requests.get(status_request_url)

    return response


#DELETE /v1/data-rights-request/{request_id}
def post_revoke(request_url, bearer_token, request_json):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.delete(request_url, json=request_json, headers=request_headers)

    return response


#POST /v1/agent/{agent-id} ("Pair-wise Key Setup" endpoint)
def post_agent(request_url, request_json):
    response = requests.post(request_url, json=request_json)

    return response


#GET /v1/agent/{agent-id} ("Agent Information" endpoint)
def get_agent(request_url, bearer_token):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.get(request_url, headers=request_headers)

    return response

