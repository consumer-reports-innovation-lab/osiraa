from django.shortcuts import render

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from nacl import signing
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey

from typing import Tuple


# AA keys should be generated offline before we start using the app and fetched from 
# the service directory.

def generate_new_pynacl_keys() -> Tuple[signing.SigningKey, signing.VerifyKey]:

    logger.info('**  agent_keys.generate_new_pynacl_keys()')

    new_signing_key = signing.SigningKey.generate()
    new_verify_key = new_signing_key.verify_key
 
    keys_json = {
        "signing_key": new_signing_key.encode(encoder=Base64Encoder).decode(),
        "verify_key": new_verify_key.encode(encoder=Base64Encoder).decode()
    }
   
    logger.info(f"**  new_signing_key = {new_signing_key}")
    logger.info(f"**  new_verify_key = {new_verify_key}")

    new_signing_key_b64 = new_signing_key.encode(encoder=Base64Encoder)
    new_verify_key_b64 = new_verify_key.encode(encoder=Base64Encoder) 

    logger.info(f"**  new_signing_key_b64 = {new_signing_key_b64}")
    logger.info(f"**  new_verify_key_b64 = {new_verify_key_b64}")

    return (signing.SigningKey(keys_json["signing_key"], encoder=Base64Encoder),
            signing.VerifyKey(keys_json["verify_key"], encoder=Base64Encoder))


'''
signing_key, verify_key = generate_new_pynacl_keys()

logger.debug(f"**  signing_key = {signing_key}")
logger.debug(f"**  verify_key = {verify_key}")

# the public key and signing key as b64 strings
signing_key_b64 = signing_key.encode(encoder=Base64Encoder)
verify_key_b64 = verify_key.encode(encoder=Base64Encoder) 

logger.debug(f"signing_key_b64 = {signing_key_b64}")
logger.debug(f"verify_key_b64 = {verify_key_b64}")
'''


def index(request):
    return render(request, 'index.html', {})

def generate_auth_agent_keys(request):
    logger.info("agent_keys.generate_auth_agent_keys()")

    signing_key, verify_key = generate_new_pynacl_keys()

    signing_key_b64 = signing_key.encode(encoder=Base64Encoder)
    verify_key_b64 = verify_key.encode(encoder=Base64Encoder) 

    context = { 
        'agent_signing_key_b64': signing_key_b64, 
        'agent_verify_key_b64': verify_key_b64, 
    }

    return render(request, 'auth_keys.html', context)

def generate_auth_agent_keys_return(request):
    return render(request, 'index.html', {})

