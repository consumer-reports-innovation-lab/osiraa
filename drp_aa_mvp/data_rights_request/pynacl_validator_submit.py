import os
import base64
import json
from urllib.request import urlopen, Request
import urllib.error
from nacl import signing
from nacl.public import PrivateKey

# Generate a private key and a signing key
signing_key = signing.SigningKey.generate()
verify_key = signing_key.verify_key

# Get the public key and signing key bytes
signing_key_bytes = signing_key.encode()
verify_key_bytes = verify_key.encode()

# Encode the public key and signing key bytes as base64
signing_key_b64 = base64.b64encode(signing_key_bytes).decode()
verify_key_b64 = base64.b64encode(verify_key_bytes).decode()

# Print the signing key
print(f"Signing key: {signing_key_b64}")
print(f"Verify key: {verify_key_b64}")

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

# Submit the signed object to the /validate endpoint
request = Request("http://localhost:8000/data_rights_request/pynacl_validate", signed_obj)
request.add_header("content-type", "application/octet-stream")
request.add_header("X-DRP-VerifyKey", verify_key_b64)
response = None
try:
    response = urlopen(request)
except urllib.error.HTTPError as e:
    print(e.read())
else:
    # Print the response
    print(response.read().decode())
