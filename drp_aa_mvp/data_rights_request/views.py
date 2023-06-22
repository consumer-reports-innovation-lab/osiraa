import base64
import datetime
import json
import os
import re
from typing import Optional, Tuple

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import arrow
import requests
import validators
from covered_business.models import CoveredBusiness
from django.core import serializers
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from nacl import signing
from nacl.encoding import HexEncoder
from nacl.public import PrivateKey
from reporting.views import (test_agent_information_endpoint, test_discovery_endpoint, test_excercise_endpoint,
                             test_status_endpoint, test_revoked_endpoint, test_pairwise_key_setup_endpoint)
from user_identity.models import IdentityUser

from .models import (DataRightsRequest, DataRightsStatus, DrpRequestStatusPair,
                     DrpRequestTransaction, IdentityPayload)

#root_utl = os.environ['REQUEST_URI']
#print (f"****  root_url = {root_utl}")

auth_agent_drp_id       = os.environ.get('OSIRAA_AA_ID', 'CR_AA_DRP_ID_001')
auth_agent_callback_url = "http://127.0.0.1:8001/update_status" #f"{os.environ.get('SERVER_NAME')}/update_status"

# todo: these keys actually should be generated offline before we start using the app
# and get them from the v0.0 service direcotry which will be a part of this dhango app, along with OSIRPIP
# for now we'll generate the keys one-time only
def load_pynacl_keys() -> Tuple[signing.SigningKey, signing.VerifyKey]:
    path = os.environ.get("OSIRAA_KEY_FILE", "./keys.json")
    if not os.path.exists(path):
        with open(path, "w") as f:
           signing_key = signing.SigningKey.generate()
           verify_key = signing_key.verify_key
           json.dump({
               "signing_key": signing_key.encode(encoder=HexEncoder).decode(),
               "verify_key": verify_key.encode(encoder=HexEncoder).decode()
           }, f)

    with open(path, "r") as f:
        jason = json.load(f)
        return (signing.SigningKey(jason["signing_key"], encoder=HexEncoder),
                signing.VerifyKey(jason["verify_key"], encoder=HexEncoder))


signing_key, verify_key = load_pynacl_keys()


# the public key and signing key as b64 strings
signing_key_hex = signing_key.encode(encoder=HexEncoder)  # remains secret, never shared, but remains with AA model
verify_key_hex = verify_key.encode(encoder=HexEncoder)    # we're going to store hex encoded verify key in the service directory
logger.debug(f"verify_key is {verify_key_hex}")

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


def setup_pairwise_key(request):
    covered_biz_id  = request.POST.get('sel_covered_biz_id')
    covered_biz     = CoveredBusiness.objects.get(pk=covered_biz_id)
    request_url     = covered_biz.api_root_endpoint + f"/v1/agent/{auth_agent_drp_id}"
    request_obj    = create_setup_pairwise_key_request_json(covered_biz.cb_id)

    signed_request  = sign_request(signing_key, request_obj)

    if (validators.url(request_url)):
        response = post_agent(request_url, signed_request)
        pairwise_setup_test_results = test_pairwise_key_setup_endpoint(request_obj, response)
        set_covered_biz_pairwise_key_params(covered_biz, response, signing_key, verify_key)

        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     pairwise_setup_test_results,
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
        agent_info_test_results = test_agent_information_endpoint(request_url, response)
        # set_agent_info_params(covered_biz)

        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
            'response_code':    response.status_code,
            'response_payload': response.text,
            'test_results':     agent_info_test_results,
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

    # todo: a missing param in the request_json could cause trouble ...
    #print('**  send_request_excercise_rights(): request_action = ' + request_action)

    request_json    = create_excercise_request_json(user_identity, covered_biz,
                                                    request_action, covered_regime)

    signed_request  = sign_request(signing_key, request_json)

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
    bearer_token    = covered_biz.auth_bearer_token
    request_id      = get_request_id (covered_biz, user_identity)

    if (request_id != None):
        if (validators.url(request_url)):
            # todo: This request SHALL contain an Bearer Token header containing the key for this AA-CB pairwise relationship in it in the form Authorization: Bearer <token>. This token is generated by calling POST /agent/{id} in section 2.06.
            response = get_status(request_url, request_id, bearer_token)

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
    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      request_url,
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

            # todo: log request to DB, stop status ping ...

            revoke_test_results = test_revoked_endpoint(request_url, response)

            context = {
                'covered_biz':      covered_biz,
                'request_url':      response.request.url,
                'response_code':    response.status_code,
                'response_payload': response.text,
                'test_results':     revoke_test_results,
            }

        else:
            request_sent_context = {
                'covered_biz':      covered_biz,
                'request_url':      request_url,
                'response_code':    'invalid url for /revoke , no response',
                'response_payload': '',
                'test_results':     [],
            }
    else:
        request_sent_context = {
            'covered_biz':      covered_biz,
            'request_url':      "/v1/data-rights-request/{{None}}",
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

def set_covered_biz_well_known_params(covered_biz, response):
    try:
        json.loads(response.text)
    except ValueError as e:
        logger.warn('**  WARNING - set_covered_biz_well_known_params(): NOT valid json  **')
        return False

    try:
        reponse_json = response.json()
        covered_biz.api_root = reponse_json['api_base']
        covered_biz.supported_actions = reponse_json['actions']
        covered_biz.save()
    except KeyError as e:
        logger.warn('**  WARNING - set_covered_biz_well_known_params(): missing keys **')
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

def sign_request(signing_key, request_obj):
    signed_obj = signing_key.sign(json.dumps(request_obj).encode())
    bencoded = base64.b64encode(signed_obj)

    return bencoded


def create_setup_pairwise_key_request_json(covered_biz_id):
    issued_time     = arrow.get()
    expires_time    = issued_time.shift(minutes=15)

    request_json = {
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz_id,
        "expires-at":   str(expires_time),
        "issued-at":    str(issued_time),
    }

    return request_json


def set_covered_biz_pairwise_key_params(covered_biz, response, signing_key, verify_key):
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
        logger.warn('**  WARNING - set_covered_biz_pairwise_key_params(): missing keys **')
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
        logger.warn('**  WARNING - set_agent_info_params(): NOT valid json  **')
        return False

    try:
        reponse_json = response.json()  # should be empty json "{ }"

        # todo: if a 403 comes back, we should revoke the old bearer key

    except KeyError as e:
        logger.warn('**  WARNING - set_agent_info_params(): missing keys **')
        return False

#--------------------------------------------------------------------------------------------------#

def create_excercise_request_json(user_identity, covered_biz, request_action, covered_regime):
    issued_time     = arrow.get()
    expires_time    = issued_time.shift(days=45)

    request_obj = {
        # 1
        "agent-id":     auth_agent_drp_id,
        "business-id":  covered_biz.cb_id,
        "expires-at":   str(expires_time),
        "issued-at":    str(issued_time),

        # 2
        "drp.version": "0.7",
        "exercise": request_action,
        "regime": covered_regime,
        "relationships": [],
        "status_callback": auth_agent_callback_url,

        # 3
        # claims in IANA JSON Web Token Claims page, see https://www.iana.org/assignments/jwt/jwt.xhtml#claims for details
        "name": (user_identity.last_name + ", " + user_identity.first_name),
        "email": user_identity.email,
        "phone_number": user_identity.phone_number,
        "address": user_identity.get_address(),
    }

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
        #request_id not sent on /excercise call
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
        # these fields need to be coerced to a datetime from arbitrary timestamps
        received_at             = enrich_date(response_json.get('received_at')),
        expected_by             = enrich_date(response_json.get('expected_by')),
        # expires_at?
    )

    #  todo: this doesn't seem to work ...
    #excercise_request = DrpRequestStatusPair.create(data_rights_request.id, data_rights_status.id)

    transaction = DrpRequestTransaction.objects.create(
        user_ref                = user_identity,
        company_ref             = covered_biz,
        request_id              = data_rights_status.request_id,
        current_status          = data_rights_status.status,
        # expires_date            = data_rights_status.expires_date,

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
    if not DrpRequestTransaction.objects.filter(user_ref=user_identity.id).exists():
        return None

    if not DrpRequestTransaction.objects.filter(user_ref=user_identity.id).filter(company_ref=covered_biz.id).exists():
        return None
    
    data_rights_transaction = DrpRequestTransaction.objects.filter(user_ref=user_identity.id).filter(company_ref=covered_biz.id)[0]

    return data_rights_transaction.request_id


#-------------------------------------------------------------------------------------------------#

#GET /.well-known/data-rights.json
def get_well_known(discovery_url, bearer_token=""):
    if bearer_token != "":
        request_headers = {'Authorization': f"Bearer {bearer_token}"}
        response = requests.get(discovery_url, headers=request_headers)
    else:
        response = requests.get(discovery_url)

    return response


#POST /v1/data-right-request/
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
