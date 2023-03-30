import json
import os
import re

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponse, HttpRequest
import arrow

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey
from nacl.utils import random
import nacl.exceptions

from .models import AuthorizedAgent

# TKTKTK cross-module import
# from data_rights_request.models import ACTION_CHOICES, REGIME_CHOICES

import logging
logger = logging.getLogger(__name__)

VERIFY_KEY_HEADER = "X-DRP-VerifyKey"
OSIRAA_PIP_CB_ID  = os.environ.get("CB_ID", "osiraa-local-001")

@csrf_exempt
def static_discovery(request):
    base = {
        "version": "0.7",
        "actions": ["sale:opt-out", "sale:opt-in", "access", "deletion"]
    }
    base["api_base"] = f"{request.scheme}://{request.get_host()}/pip/",
    return JsonResponse(base)

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
    """
    urlconfs can't choose a route based on method so we'll do it ourselves
    I really do hate django.
    """
    if request.method == 'GET':
        agent_status(request, aa_id)
    elif request.method == 'POST':
        register_agent(request, aa_id)


def register_agent(request, aa_id: str):
    agent = AuthorizedAgent.fetch_by_id(aa_id)
    if agent is None:
        # Validate That the signature validates to the key associated with the out of band Authorized Agent identity presented in the request path.
        logger.error(f"could not find authorized agent for {aa_id}")
        return HttpResponse(status=403)

    try:
        message = validate_message_to_agent(agent, request)
    except:
        return HttpResponse(status=403)

    # make a token and persist it...
    agent.bearer_token = HexEncoder.encode(random(size=64)).decode()
    try:
        agent.save()
        return  JsonResponse({
            "agent-id": message["agent-id"],
            "token":    agent.bearer_token
        })
    except:
        return HttpResponse(b"Something went wonky! Token did not persist.", status=500)

@csrf_exempt
def agent_status(request, aa_id: str):
    """
    This method just looks to see that the bearer token is in the DB.
    """
    auth_header = request.headers.get("Authorization")
    extractor = r"Bearer ([a-zA-Z0-9=+\-_/]*)"
    matches = re.match(extractor, auth_header)
    if matches is None:
        logger.error(f"Auth header did not parse.")
        return HttpResponse(status=403)
    btok = matches.group(1)

    agent = AuthorizedAgent.fetch_by_bearer_token(btok)

    if agent.aa_id != aa_id:
        logger.error(f"bearer token did not match expected AA {aa_id}???")
        return HttpResponse(status=403)

    if agent is None:
        logger.error(f"tok did not resolve to agent; caller expected {aa_id}")
        return HttpResponse(status=403)

    return JsonResponse({})



@csrf_exempt
def validate_pynacl(request):
    pass


@csrf_exempt
def request_handler(request, request_id: str):
    pass

def validate_message_to_agent(agent: AuthorizedAgent, request: HttpRequest) -> dict:
    """Validate the message is coming from the specified agent and
    destined to us in a reasonable time window. Returns the
    deserialized message or raises.
    """
    now = arrow.get()

    aa_id = agent.aa_id
    verify_key_hex = agent.verify_key
    verify_key = VerifyKey(verify_key_hex, encoder=HexEncoder)

    try:
        # don't need to do anything here -- if it doesn't raise it's verified!
        serialized_message = verify_key.verify(request.body)
    except nacl.exceptions.BadSignatureError as e:
        # Validate That the signature validates to the key associated with the out of band Authorized Agent identity presented in the request path.
        logger.error(f"bad signature from {aa_id}: {e}")
        raise e

    message = json.loads(serialized_message)

    aa_id_claim = message["agent-id"]
    if aa_id_claim != aa_id:
        # Validate that the Authorized Agent specified in the agent-id claim in the request matches the Authorized Agent associated with the presented Bearer Token
        logger.error(f"outer aa {aa_id} doesn't match claim {aa_id_claim}!!")
        raise Exception()

    business_id_claim = message["business-id"]
    if business_id_claim != OSIRAA_PIP_CB_ID:
        # - That they are the Covered Business specified inside the business-id claim
        logger.error(f"claimed business-id {business_id_claim} does not match expected {OSIRAA_PIP_CB_ID}")
        raise Exception()

    expires_at_claim = message["expires-at"]
    if now > arrow.get(expires_at_claim):
        # TKTKTK: maybe worth checking that it's within like 15 minutes or something just to be sure the AA is compliant?
        # - That the current time is after the Timestamp issued-at claim
        logger.error(f"Message has expired! {expires_at_claim}")
        raise Exception()

    issued_at_claim = message["issued-at"]
    if arrow.get(issued_at_claim) > now:
        # - That the current time is before the Expiration expires-at claim
        logger.error(f"Message from the future??? {issued_at_claim}")
        raise Exception()

    return message
