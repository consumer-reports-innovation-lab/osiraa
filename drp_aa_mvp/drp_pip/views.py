from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from typing import List

from nacl.encoding import Base64Encoder
from nacl.signing import VerifyKey
import nacl.exceptions
import json
from datetime import datetime

# TKTKTK cross-module import
from data_rights_request.models import ACTION_CHOICES, REGIME_CHOICES

VERIFY_KEY_HEADER = "X-DRP-VerifyKey"

@csrf_exempt
def static_discovery(request):
    base = {
        "version": "0.7",
        "actions": ["sale:opt-out", "sale:opt-in", "access", "deletion"]
    }
    base["api_base"] = f"{request.scheme}://{request.get_host()}/pip/",
    return JsonResponse(base)

@csrf_exempt
def register_agent(request):
    pass

@csrf_exempt
def agent_status(request):
    pass


@csrf_exempt
def validate_pynacl(request):
    '''Validate an application/octet-stream request containing the
    NaCL signed token with the verify key stuffed in to a header,
    base64 encoded.

    This method DOES NOT do a validation sufficient enough to be a
    drop-in validator for DRP Data Rights Requests and only exists to
    exhibit the cryptographic signing/verifying flows via PyNaCl. Keys
    SHOULD NOT be sent in-band in this method as no real trust root is
    established.

    As the DRP public key directories are designed this code will be
    iterated upon as a test-bed for this network operating model.
    '''

    context = dict(valid=True,
                   reasons=list())

    # TKTKTK add model for drp_pip.authorized_agent w/ this key in it.
    if VERIFY_KEY_HEADER not in request.headers:
      context["valid"] = False
      context["reasons"] += [f"No {VERIFY_KEY_HEADER} in request"]
      return render(request, 'drp_pip/validate_pynacl.html', context)

    verify_key = VerifyKey(
        request.headers.get(VERIFY_KEY_HEADER),
        encoder=Base64Encoder
    )

    verified_obj = bytes()
    try:
      blob = request.read()
      verified_obj = verify_key.verify(blob)
    except nacl.exceptions.BadSignatureError:
      context["valid"] = False
      context["reasons"] += [f"BadSignatureError raised"]
      return render(request, 'drp_pip/validate_pynacl.html', context)

    verified_dict = dict()
    try:
      verified_dict = json.loads(verified_obj)
    except json.JSONDecodeError:
      context["valid"] = False
      context["reasons"] += [f"JSONDecodeError raised"]
      return render(request, 'drp_pip/validate_pynacl.html', context)

    context = validate_inner_dict(verified_dict, context)

    # TKTKTK persist request to DB for the request_handler endpoint
    
    return render(request, 'drp_pip/validate_pynacl.html', context)


def validate_inner_dict(obj: dict, context: dict):
    '''validate fields of obj as a verified, deserialized DataRightsRequest

    TODO: shove this in to the 0.6-schema model object and call
    is_valid() on it, but for now we just check keys exist etc.
    '''
    check_fields = ["iss", "aud", "exp", "iat"]
    for field in check_fields:
        if field not in obj:
            context["valid"] = False
            context["reasons"] += [f"{field} is missing in object"]

    check_datetime_fields = ["exp", "iat"]
    for field in check_datetime_fields:
        try:
            datetime.fromisoformat(obj[field])
        except ValueError:
            context["valid"] = False
            context["reasons"] += [f"{field} is not ISO 8601"]


    ver = obj.get("drp.version", None)
    if ver != "0.6":
        context["valid"] = False
        context["reasons"] += [f"DRP version {ver} is not 0.6"]

    right = obj.get("exercise", None)
    # extract from tuple
    if right not in [action[1] for action in ACTION_CHOICES]:
        context["valid"] = False
        context["reasons"] += [f"{right} not in valid actions"]

    regime = obj.get("regime", None)
    # extract from tuple
    if regime not in [regime[1] for regime in REGIME_CHOICES]:
        context["valid"] = False
        context["reasons"] += [f"{regime} not valid"]

    shall_claims = ["name", "email", "email_verified"]
    for field in shall_claims:
        if field not in obj:
            context["valid"] = False
            context["reasons"] += [f"{field} is missing in object"]

    may_claims = ["phone_number", "phone_number_verified", "address", "address_verified", "power_of_attorney"]
    for field in may_claims:
        if field not in obj:
            context["reasons"] += [f"{field} is missing in object"]

    return context


@csrf_exempt
def request_handler(request):
    pass


