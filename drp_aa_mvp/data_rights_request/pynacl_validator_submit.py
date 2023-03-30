import os
import base64
import json
from typing import Tuple
from urllib.request import urlopen, Request
import urllib.error
import logging

from nacl import signing
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

LOCAL_VALIDATOR_URL = "http://localhost:8000/data_rights_request/pynacl_validate"


def generate_keys() -> Tuple[str, str]:
    '''
    Returns tuple with signing and verify key
    '''
    # Generate a private key and a signing key
    # these are `bytes' objects
    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key

    return (signing_key, verify_key)

def make_req(signing_key):
    '''
    return a serialized JSON blob signed with the given PyNaCl signing key
    '''

    # Create the object to sign
    obj = {
        "iss": "issuer",
        "aud": "audience",
        "exp": "2022-12-31T23:59:59.999999Z",
        "iat": "2022-12-04T10:14:00Z"
    }

    # Sign the object
    signed_obj = signing_key.sign(json.dumps(obj).encode())

    print(signed_obj)
    return signed_obj

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


if __name__ == "__main__":
    print("Running...")
    print(submit_signed_request(LOCAL_VALIDATOR_URL))
