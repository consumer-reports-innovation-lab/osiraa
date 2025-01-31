import arrow
import base64
from datetime import datetime, timezone, timedelta

import json
import re           # regex library
import requests
import validators

from typing import Optional, Tuple

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from django.conf import settings
from django.shortcuts import render

from nacl import signing
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey

from .models import (DataRightsRequest, DataRightsStatus, DrpRequestTransaction, IdentityPayload)

from covered_business.models import CoveredBusiness
from reporting.views import (test_agent_information_endpoint, test_exercise_endpoint, #test_discovery_endpoint, 
                             test_status_endpoint, test_revoked_endpoint, test_pairwise_key_setup_endpoint)
from user_identity.models import IdentityUser

import drp_pip.models


auth_agent_drp_id           = settings.AUTHORIZED_AGENT_ID
auth_agent_drp_name         = settings.AUTHORIZED_AGENT_NAME
auth_agent_callback_url     = settings.WEB_URL + '/update_status'  #'http://127.0.0.1:8003/update_status'

service_directory_agents_url      = settings.SERVICE_DIRECTORY_AGENT_URL
service_directory_businesses_url  = settings.SERVICE_DIRECTORY_BUSINESS_URL


# get the (b64-encoded) keys from environment vars (or the vault if the app is deployed) ...
# signing key must remain secret
settings_signing_key = settings.AGENT_SIGNING_KEY_B64

# verify key must match the key stored in the service directory
settings_verify_key  = settings.AGENT_VERIFY_KEY_B64

logger.info(f"**  settings_signing_key = {settings_signing_key}")
logger.info(f"**  settings_verify_key = {settings_verify_key}")

# create encoded keys from the strings loaded in from the settings ...
def encode_keys() -> Tuple[signing.SigningKey, signing.VerifyKey]:
    return (signing.SigningKey(settings_signing_key, encoder=Base64Encoder),
            signing.VerifyKey(settings_verify_key, encoder=Base64Encoder))

signing_key, verify_key = encode_keys() 

#logger.debug(f"signing_key = {signing_key}")
#logger.debug(f"verify_key = {verify_key}")

# the public key and signing key as b64 strings
signing_key_b64 = signing_key.encode(encoder=Base64Encoder)
verify_key_b64  = verify_key.encode(encoder=Base64Encoder) 

auth_agent_signing_key = signing_key_b64
auth_agent_verify_key  = verify_key_b64

logger.info(f"**  auth_agent_drp_id         = {auth_agent_drp_id}")
logger.info(f"**  auth_agent_drp_name       = {auth_agent_drp_name}")
logger.info(f"**  auth_agent_callback_url   = {auth_agent_callback_url}")
logger.info(f"**  auth_agent_signing_key    = {auth_agent_signing_key}")
logger.info(f"**  auth_agent_verify_key     = {auth_agent_verify_key}")

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


# call to the service directory returns the info for all CB's
def refresh_service_directory_data (request):
    request_url = service_directory_businesses_url
    response = get_service_directory_covered_biz(request_url)

    try:
        response_json = json.loads(response.text)
    except ValueError as e:
        logger.warn('**  WARNING - refresh_service_directory_data(): NOT valid json  **')
        return False 
    
    for response_item in response_json:
        covered_biz_cb_id = str(response_item['id'])  # corresponds to cb_id in the CovereredBusiness model
        covered_biz_id    = get_covered_biz_id_from_cb_id(covered_biz_cb_id)  # index to lookup the object

        if covered_biz_id is not None:
            covered_biz = CoveredBusiness.objects.get(pk=covered_biz_id)
            update_covered_biz_params_from_service_directory(covered_biz, response_item)
        else:
            create_covered_biz_db_entry_from_service_directory(response_item)    
     
        # todo: handle case where SD enrty is removed - mark CB in DB as 'removed' ...

    drp_pip.models.AuthorizedAgent.refresh_from_directory(service_directory_agents_url)

    user_identities             = IdentityUser.objects.all()
    covered_businesses          = CoveredBusiness.objects.all()
    covered_biz_id              = request.POST.get('sel_covered_biz_id')
    request_actions             = get_request_actions_form_display(selected_covered_biz)

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


def setup_pairwise_key(request):   # a.k.a. regsiter agent
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    request_url     = covered_biz.api_root_endpoint + f"/v1/agent/{auth_agent_drp_id}"
    request_obj     = create_setup_pairwise_key_request_json(covered_biz.cb_id)
    signed_request  = sign_request(signing_key, request_obj)

    #logger.info('**  setup_pairwise_key(): request_url = ' + request_url)

    if (validators.url(request_url)):
        response = post_agent(request_url, signed_request)
        pairwise_setup_test_results = test_pairwise_key_setup_endpoint(request_obj, response)

        set_covered_biz_pairwise_key_params(covered_biz, response)

        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'request_obj':      request_obj,
            'signed_request':   signed_request,
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     pairwise_setup_test_results,
        }

    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'request_obj':      request_obj,
            'signed_request':   signed_request,
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

    #logger.info('**  get_agent_information(): request_url = ' + request_url)

    if (validators.url(request_url)):
        response = get_agent(request_url, bearer_token)
        agent_info_test_results = test_agent_information_endpoint(request_url, response)
        # set_agent_info_params(covered_biz)

        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     agent_info_test_results,
        }

    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'response_code':    'invalid url for /get_agent_information, no response',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def send_request_exercise_rights(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    user_id_id      = request.POST.get('user_identity')
    user_identity   = IdentityUser.objects.get(pk=user_id_id)
    request_action  = request.POST.get('request_action')
    covered_regime  = request.POST.get('covered_regime')

    # note - removed trailing slash
    request_url     = covered_biz.api_root_endpoint + "/v1/data-rights-request"
    bearer_token    = covered_biz.auth_bearer_token

    logger.info(f'**  send_request_exercise_rights(): request_url = {request_url}')

    # todo: a missing param in the request_json could cause trouble ...
    #logger.info('**  send_request_exercise_rights(): request_action = ' + request_action)

    request_json    = create_exercise_request_json(user_identity, covered_biz, request_action, covered_regime)
    #logger.info(f'**  send_request_exercise_rights(): request_json = {request_json}')

    signed_request  = sign_request(signing_key, request_json)
    #logger.info(f'**  send_request_exercise_rights(): signed_request = {signed_request}')

    if (validators.url(request_url)):
        response = post_exercise_rights(request_url, bearer_token, signed_request)

        try:
            json.loads(response.text)
        except ValueError as e:
            request_sent_context = {
                'covered_biz':      covered_biz,
                'request_url':      request_url,
                'agent_verify_key': auth_agent_verify_key,
                'request_obj':      request_json,
                'signed_request':   signed_request,
                'response_code':    response.status_code,
                'response_payload': 'invalid json in response for /v1/data-rights-request',
                'test_results':     [],
            }

            return render(request, 'data_rights_request/request_sent.html', request_sent_context)

        response_json = response.json()

        if ('request_id' in response_json):
            data_rights_transaction: DrpRequestTransaction = create_drp_request_transaction(user_identity,
                                                            covered_biz, request_json, response_json)

        exercise_test_results = test_exercise_endpoint(request_json, response)

        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'request_obj':      request_json,
            'signed_request':   signed_request,
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     exercise_test_results
        }

    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'request_obj':      request_json,
            'signed_request':   signed_request,
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
    bearer_token    = covered_biz.auth_bearer_token
    request_id      = get_request_id (covered_biz, user_identity)

    if (request_id != None):
        if (validators.url(request_url)):
            # This request SHALL contain an Bearer Token header containing the key for this AA-CB pairwise relationship in it in the form Authorization: Bearer <token>. This token is generated by calling POST /agent/{id} in section 2.06.
            response = get_status(request_url, request_id, bearer_token)

            status_test_results = test_status_endpoint(request_url, response)

            request_sent_context = {
                'covered_biz':      covered_biz,
                'request_url':      response.request.url,
                'agent_verify_key': auth_agent_verify_key,
                'response_code':    response.status_code,
                'response_payload': response.text,
                'test_results':     status_test_results
            }
        else:
            request_sent_context = {
                'covered_biz':      covered_biz,
                'request_url':      request_url,
                'agent_verify_key': auth_agent_verify_key,
                'response_code':    'invalid url for /status , no response',
                'response_payload': '',
                'test_results':     [],
            }
    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'agent_verify_key': auth_agent_verify_key,
            'response_code':    'no request id for this user and covered business, request not sent',
            'response_payload': '',
            'test_results':     [],
        }

    return render(request, 'data_rights_request/request_sent.html', request_sent_context)


def send_request_revoke(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    user_id_id      = request.POST.get('user_identity')
    user_identity   = IdentityUser.objects.get(pk=user_id_id)
    bearer_token    = covered_biz.auth_bearer_token
    request_id      = get_request_id (covered_biz, user_identity)

    if (request_id != None):
        reason          = "I don't want my account deleted."
        request_url     =  "/v1/data-rights-request/" + str(request_id)
        request_json    = create_revoke_request_json(reason)
        signed_request  = sign_request(signing_key, request_json)

        if (validators.url(request_url)):
            response = post_revoke(request_url, bearer_token, signed_request)
            revoke_test_results = test_revoked_endpoint(request_url, response)

            context = {
                'covered_biz':      covered_biz,
                'request_url':      response.request.url,
                'request_obj':      request_json,
                'signed_request':   signed_request,
                'response_code':    response.status_code,
                'response_payload': response.text,
                'test_results':     revoke_test_results,
            }

        else:
            request_sent_context = {
                'covered_biz':      covered_biz,
                'request_url':      request_url,
                'agent_verify_key': auth_agent_verify_key,
                'request_obj':      request_json,
                'signed_request':   signed_request,
                'response_code':    'invalid url for /revoke , no response',
                'response_payload': '',
                'test_results':     [],
            }
    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      "/v1/data-rights-request/{{None}}",
            'agent_verify_key': auth_agent_verify_key,
            'response_code':    'no request id for this user and covered business, request not sent',
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

def get_covered_biz_id_from_cb_id(covered_biz_cb_id):
    covered_businesses = CoveredBusiness.objects.all()

    for covered_biz in covered_businesses:
        if covered_biz.cb_id == covered_biz_cb_id:
            return covered_biz.id
     
    return None


def update_covered_biz_params_from_service_directory(covered_biz, params_json):
    try:
        covered_biz.api_root = params_json['api_base']
        covered_biz.supported_actions = params_json['supported_actions']
        
        if 'supported_verifications' in params_json:
            covered_biz.supported_verifications = params_json['supported_verifications']

        covered_biz.save()
    except KeyError as e:
        logger.warn('**  WARNING - update_covered_biz_params_from_service_directory(): missing keys **')
        raise e

def create_covered_biz_db_entry_from_service_directory(params_json):
    try:
        cb_id                   = params_json['id']
        name                    = params_json['name']
        logo                    = params_json['logo']
        api_root_endpoint       = params_json['api_base']
        supported_actions       = params_json['supported_actions']


        new_covered_biz     = CoveredBusiness.objects.create(name=name, cb_id=cb_id, logo=logo, 
                                api_root_endpoint=api_root_endpoint, supported_actions=supported_actions)

        if 'supported_verifications' in params_json:
            supported_verifications = params_json['supported_verifications']
            new_covered_biz.supported_verifications = supported_verifications

    except KeyError as e:
        logger.warn('**  WARNING - create_covered_biz_db_entry_from_service_directory(): missing keys **')
        raise e


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

def sign_request(signing_key, request_obj):
    signed_obj = signing_key.sign(json.dumps(request_obj).encode())
    b64encoded = base64.b64encode(signed_obj)

    return b64encoded


def create_setup_pairwise_key_request_json(covered_biz_id):
    issued_time         = datetime.now(timezone.utc)
    expires_time        = issued_time + timedelta(minutes=15)  # 15 minutes from now
    issued_timestamp    = issued_time.isoformat(timespec='milliseconds')
    expires_timestamp   = expires_time.isoformat(timespec='milliseconds')

    request_json = {
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz_id,
        "issued-at":    issued_timestamp,
        "expires-at":   expires_timestamp,
    }

    #logger.info(f"**  create_setup_pairwise_key_request_json(): request_json = {request_json}")

    return request_json


def set_covered_biz_pairwise_key_params(covered_biz, response):
    try:
        json.loads(response.text)
    except ValueError as e:
        logger.warn('**  WARNING - set_covered_biz_pairwise_key_params(): NOT valid json  **')
        return False

    try:
        response_json = response.json()

        if not('agent-id' in response_json) or (response_json['agent-id'] != auth_agent_drp_id):
            return False

        if not('token' in response_json) or (response_json['token'] == ''):
            return False

        covered_biz.auth_bearer_token = response_json['token']
        covered_biz.save()

    except KeyError as e:
        logger.warn('**  WARNING - set_covered_biz_pairwise_key_params(): missing token **')
        return False


def create_agent_key_setup_json(agent_id, business_id):
    issued_time     = datetime.now(timezone.utc)
    expires_time    = issued_time + timedelta(minutes=15)  # 15 minutes from now
    issued_timestamp = issued_time.isoformat(timespec='milliseconds')
    expires_timestamp = expires_time.isoformat(timespec='milliseconds')

    agent_key_setup_json = {
        "agent-id": agent_id,
        "business-id": business_id,
        "issued-at": issued_timestamp,
        "expires-at": expires_timestamp,
    }
    
    #logger.info(f"**  create_agent_key_setup_json(): agent_key_setup_json = {agent_key_setup_json}")

    return agent_key_setup_json


def set_agent_info_params(response):
    try:
        json.loads(response.text)
    except ValueError as e:
        logger.warn('**  WARNING - set_agent_info_params(): NOT valid json  **')
        return False

    try:
        reponse_json = response.json()  # should be empty json "{ }"

        # todo: if a 403 comes back, we should revoke the old bearer key

    except KeyError as e:
        logger.warn('**  WARNING - set_agent_info_params(): missing keys **')
        return False


#--------------------------------------------------------------------------------------------------#

def create_exercise_request_json(user_identity, covered_biz, request_action, covered_regime):
    issued_time         = datetime.now(timezone.utc)
    expires_time        = issued_time + timedelta(minutes=15)  # 15 minutes from now
    issued_timestamp    = issued_time.isoformat(timespec='milliseconds')
    expires_timestamp   = expires_time.isoformat(timespec='milliseconds')

    request_obj = {
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz.cb_id,
        "issued-at":    issued_timestamp,
        "expires-at":   expires_timestamp,
        "drp.version": "0.9.4",
        "exercise": request_action,
        "regime": covered_regime,
        "status_callback": auth_agent_callback_url,
        "name": (user_identity.last_name + ", " + user_identity.first_name),
    }

    # identity claims, see https://www.iana.org/assignments/jwt/jwt.xhtml#claims for details
    if "email" in covered_biz.supported_verifications:
        request_obj["email"] = user_identity.email
        request_obj["email_verified"] = user_identity.email_verified

    if "phone" in covered_biz.supported_verifications:
        request_obj["phone_number"] = user_identity.phone_number
        request_obj["phone_number_verified"] = user_identity.phone_verified

    if "address" in covered_biz.supported_verifications:
        request_obj["address"] = user_identity.get_address_json()
        request_obj["address_verified"] = user_identity.address_verified

    logger.info(f"**  create_exercise_request_json(): request_obj = {request_obj}")

    return request_obj


def create_revoke_request_json(reason):
    request_obj = {
        "reason": reason
    }

    return request_obj


#-------------------------------------------------------------------------------------------------#

def create_drp_request_transaction(user_identity, covered_biz, request_json, response_json):
    identity_payload = IdentityPayload.objects.create(
        issuer                  = request_json.get("agent-id"),
        audience                = request_json.get("business-id"),
        name                    = user_identity.get_full_name(),
        email                   = user_identity.email,
        email_verified          = user_identity.email_verified,
        phone_number            = user_identity.phone_number,
        phone_number_verified   = user_identity.phone_verified,
        # this needs to get decomposed in to details!
        # address                 = user_identity.get_address(),
        address_verified        = user_identity.address_verified,
        power_of_attorney       = user_identity.power_of_attorney,
    )

    data_rights_request = DataRightsRequest.objects.create(
        #request_id not sent on /exercise call
        #meta                    = request_json['meta'],
        relationships           = request_json['relationships'],
        status_callback         = request_json['status_callback'],
        regime                  = request_json['regime'],
        right                   = request_json['exercise'],
        #identity                = request_json['identity'],
    )

    data_rights_status = DataRightsStatus.objects.create(
        # required fields
        request_id              = response_json['request_id'],
        status                  = response_json['status'],
        # optional/possible fields
        processing_details      = response_json.get('processing_details'),
        reason                  = response_json.get('reason'),
        user_verification_url   = response_json.get('user_verification_url'),
        # coerce to a datetime object from timestamp string
        received_at             = enrich_date(response_json.get('received_at')),
        expected_by             = enrich_date(response_json.get('expected_by')),
        # expires_at?
    )

    #  todo: this doesn't seem to work ...
    #exercise_request = DrpRequestStatusPair.create(data_rights_request.id, data_rights_status.id)

    transaction = DrpRequestTransaction.objects.create(
        user_ref                = user_identity,
        company_ref             = covered_biz,
        request_id              = data_rights_status.request_id,
        current_status          = data_rights_status.status,
        # expires_date            = data_rights_status.expires_date,
        is_final                = False,
        #exer_request           = exercise_request
    )

    return transaction


def enrich_date(dt: Optional[str]):
    # arrow.get returns "now" if you pass it None -- we want to just not persist anything in that case.
    if dt is None:
        return None

    # additionally, munge the input string to drop RFC3339 characters which are incorrectly parsed as timestamps
    if re.search(r'-[0-9]{4}$', dt):
        dt = dt[:-5] # sickos.jpg

    return arrow.get(dt).datetime


def get_request_id (covered_biz, user_identity):
    if not DrpRequestTransaction.objects.filter(user_ref=user_identity.id).exists():
        return None

    if not DrpRequestTransaction.objects.filter(user_ref=user_identity.id).filter(company_ref=covered_biz.id).exists():
        return None
    
    data_rights_transaction = DrpRequestTransaction.objects.filter(user_ref=user_identity.id).filter(company_ref=covered_biz.id)[0]

    return data_rights_transaction.request_id


#-------------------------------------------------------------------------------------------------#

#GET https://discovery.datarightsprotocol.org/businesses.json
def get_service_directory_covered_biz (service_dir_biz_url):
    response = requests.get(service_dir_biz_url)
    return response


#GET /.well-known/data-rights.json
'''
def get_well_known(discovery_url, bearer_token=""):
    if bearer_token != "":
        request_headers = {'Authorization': f"Bearer {bearer_token}"}
        response = requests.get(discovery_url, headers=request_headers)
    else:
        response = requests.get(discovery_url)

    return response
'''


#POST /v1/data-rights-request/
def post_exercise_rights(request_url, bearer_token, signed_request):
    request_headers = {
        'Authorization': f"Bearer {bearer_token}",
        'Content-Type': "text/plain"
    }
    response = requests.post(request_url, headers=request_headers, data=signed_request)

    return response


# GET /v1/data-rights-request/{request_id}
def get_status(request_url, request_id, bearer_token):
    status_request_url = request_url + request_id
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.get(status_request_url, headers=request_headers)

    return response


#DELETE /v1/data-rights-request/{request_id}
def post_revoke(request_url, bearer_token, signed_request):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.delete(request_url, data=signed_request, headers=request_headers)

    return response


#POST /v1/agent/{agent-id} ("Pair-wise Key Setup" endpoint)
def post_agent(request_url, signed_request):
    request_headers = {
        'Content-Type': "text/plain"
    }
    response = requests.post(request_url, headers=request_headers, data=signed_request)

    return response


#GET /v1/agent/{agent-id} ("Agent Information" endpoint)
def get_agent(request_url, bearer_token):
    request_headers = {'Authorization': f"Bearer {bearer_token}"}
    response = requests.get(request_url, headers=request_headers)

    return response

def identity_verification(request):
    return render(request, 'data_rights_request/identity_verification.html', {})
