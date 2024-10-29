import base64
import json
import os
import re
from typing import Optional
import uuid

import arrow
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponse, HttpRequest
from nacl.encoding import Base64Encoder
from nacl.signing import VerifyKey
from nacl.utils import random
import nacl.exceptions

from .models import (AuthorizedAgent, MessageValidationException,
                     DataRightsRequest, DataRightsStatus)
from data_rights_request.models import ACTION_CHOICES, REGIME_CHOICES

# todo: cross-module import ...
# from data_rights_request.models import ACTION_CHOICES, REGIME_CHOICES

import logging
logging.basicConfig(level=logging.WARN)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OSIRAA_PIP_CB_ID  = os.environ.get("OSIRAA_PIP_CB_ID", "osiraa-local-001")


"""
Privacy Infrastructure Providers MUST validate the message in this order:

# Validate That the signature validates to the key associated with the out of band Authorized Agent identity presented in the Bearer Token.
- That the Authorized Agent specified in the agent-id claim in the request matches the Authorized Agent associated with the presented Bearer Token
- That they are the Covered Business specified inside the business-id claim
- That the current time is after the Timestamp issued-at claim
- That the current time is before the Expiration expires-at claim
"""

@csrf_exempt
@require_http_methods(["GET", "POST"])
def agent(request, aa_id: str):
    logger.info('**  drp_pip.agent()')

    # urlconfs can't choose a route based on method so we'll do it ourselves
    if request.method == 'POST':
        return register_agent(request, aa_id)
    elif request.method == 'GET':
        return agent_status(request, aa_id)
    

@csrf_exempt
def register_agent(request, aa_id: str):
    logger.info('**  drp_pip.register_agent()')

    agent = AuthorizedAgent.fetch_by_id(aa_id)
    logger.info(f'**  drp_pip.register_agent(): agent = {agent}')

    if agent is None:
        # validate that the signature validates to the key associated with the out of band Authorized Agent identity presented in the request path
        logger.error(f"could not find authorized agent for {aa_id}")
        return HttpResponse(status=403)

    try:
        message = validate_message_to_agent(agent, request)
    except:
        return HttpResponse(status=403)

    # make a token and persist it...
    agent.bearer_token = Base64Encoder.encode(random(size=64)).decode()

    try:
        agent.save()

        return  JsonResponse({
            "agent-id": message["agent-id"],
            "token":    agent.bearer_token
        })
    except:
        return HttpResponse(b"Something went wonky! Token did not persist.", status=500)


def validate_auth_header(request) -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    extractor = r"Bearer ([a-zA-Z0-9=+\-_/]+)"
    matches = re.match(extractor, auth_header)

    if matches is None:
        logger.error(f"validate_auth_header(): Auth header '{auth_header}' did not parse")
        return None

    return matches.group(1)


@csrf_exempt
def agent_status(request, aa_id: str):
    logger.info('**  drp_pip.agent_status()')

    # this method just looks to see that the bearer token is in the DB.
    bearer_token = validate_auth_header(request)
    if not bearer_token:
        return HttpResponse(status=403)

    agent = AuthorizedAgent.fetch_by_bearer_token(bearer_token)

    if agent.aa_id != aa_id:
        logger.error(f"bearer token did not match expected AA {aa_id}")
        return HttpResponse(status=403)

    if agent is None:
        logger.error(f"token did not resolve to agent; caller expected {aa_id}")
        return HttpResponse(status=403)

    return JsonResponse({})


@csrf_exempt
def exercise(request: HttpRequest):
    bearer_token = validate_auth_header(request)
    if not bearer_token:
        return HttpResponse(status=403)

    agent = AuthorizedAgent.fetch_by_bearer_token(bearer_token)

    try:
        message = validate_message_to_agent(agent, request)
    except:
        return HttpResponse(status=403)

    request_id = uuid.uuid4()

    db_right = next(filter(lambda t: { t[1] == message['exercise'] }, ACTION_CHOICES))[0]
    db_regime = next(filter(lambda t: { t[1] == message['regime'] }, REGIME_CHOICES))[0]

    # we now have a dict with the DRP request in it, the message has been
    # authenticated to the key associated with the bearer token!
    data_rights_request = DataRightsRequest.objects.create(
        aa_id                   = agent.aa_id,
        request_id              = request_id,
        relationships           = message['relationships'],
        status_callback         = message['status_callback'],
        regime                  = db_regime,
        right                   = db_right,
        # todo: persist claims ... ?
    )

    status = dict(
        # required fields
        request_id              = request_id,
        status                  = 'open',
        # optional/possible fields
        # processing_details      = response_json.get('processing_details'),
        # reason                  = response_json.get('reason'),
        # user_verification_url   = response_json.get('user_verification_url'),
        received_at             = str(arrow.get())
        # expected_by             = enrich_date(response_json.get('expected_by')),
    )

    data_rights_status = DataRightsStatus.objects.create(
        aa_id                   = agent.aa_id,
        **status
    )

    return JsonResponse(status)

@csrf_exempt
def get_status(request, request_id: str):
    bearer_token = validate_auth_header(request)
    if not bearer_token:
        logger.error(f"no bearer token")
        return HttpResponse(status=403)

    agent = AuthorizedAgent.fetch_by_bearer_token(bearer_token)
    status = DataRightsStatus.objects.get(request_id=request_id)

    if agent.aa_id != status.aa_id:
        logger.error(f"agent ID didnt match!")
        return HttpResponse(status=403)

    return JsonResponse(dict(
        # required fields
        request_id              = status.request_id,
        status                  = status.status,
        # optional/possible fields
        processing_details      = status.processing_details,
        reason                  = status.reason,
        user_verification_url   = status.user_verification_url,
        # these fields need to be coerced to a datetime from arbitrary timestamps
        received_at             = status.received_at,
        expected_by             = status.expected_by,
    ))


def validate_message_to_agent(agent: AuthorizedAgent, request: HttpRequest) -> dict:
    # validate that the message is coming from the specified agent and destined to us in a reasonable time window 
    # returns the deserialized message or raises an exception

    logger.info(f"**  validate_message_to_agent()")

    now = arrow.get()

    aa_id = agent.aa_id
    
    # todo: verify this is the correctly encoded verify key
    verify_key_b64 = agent.verify_key

    # todo: what does this do?  why to we need to unencode it?
    verify_key = VerifyKey(verify_key_b64, encoder=Base64Encoder)

    logger.debug(f"verify_key_b64 is {verify_key_b64}")
    logger.debug(f"authourized_agent_id is {aa_id}")

    decoded = base64.b64decode(request.body)
    logger.debug(f"decoded is {decoded}")
    logger.debug(f"encoded is {request.body}")

    try:
        # don't need to do anything here -- if it doesn't raise it's verified!
        serialized_message = verify_key.verify(decoded)
    except nacl.exceptions.BadSignatureError as e:
        # Validate That the signature validates to the key associated with the out of band Authorized Agent identity presented in the request path.
        logger.error(f"bad signature from {aa_id}: {e}")
        raise e

    message = json.loads(serialized_message)

    aa_id_claim = message["agent-id"]
    if aa_id_claim != aa_id:
        # validate that the Authorized Agent specified in the agent-id claim in the request matches the Authorized Agent associated with the presented Bearer Token
        raise MessageValidationException(f"outer aa {aa_id} doesn't match claim {aa_id_claim}!!")

    business_id_claim = message["business-id"]
    if business_id_claim != OSIRAA_PIP_CB_ID:
        # validate that they are the Covered Business specified inside the business-id claim
        raise MessageValidationException(f"claimed business-id {business_id_claim} does not match expected {OSIRAA_PIP_CB_ID}")

    expires_at_claim = message["expires-at"]
    if now > arrow.get(expires_at_claim):
        # validate that the current time is after the Timestamp issued-at claim
        # todo: check that it's within like 15 minutes or so just to be sure the AA is compliant ... ?
        raise MessageValidationException(f"Message has expired! {expires_at_claim}")

    issued_at_claim = message["issued-at"]
    if arrow.get(issued_at_claim) > now:
        # validate that the current time is before the Expiration expires-at claim
        raise MessageValidationException(f"Message from the future??? {issued_at_claim}")

    return message
