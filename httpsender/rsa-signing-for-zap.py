# RSA Signing Script for Zed Attack Proxy - ZAP
# HelpAddOn Script - HTTPSender
# Michal Walkowski - https://mwalkowski.github.io/
# https://github.com/mwalkowski
#
# Tested with Jython 14 beta and ZAP 2.14.0
# For RSA Signing Process: https://httpwg.org/http-extensions/draft-ietf-httpbis-message-signatures.html#name-rsassa-pkcs1-v1_5-using-sha
# Based On: https://mwalkowski.github.io/post/using-burp-python-scripts-to-sign-requests-with-rsa-keys/

import urlparse
import uuid
import datetime
import base64
import subprocess

# path to private.key
PRIVATE_KEY = "private.key"
SIGNATURE_HEADER = 'X-Signature'
NONCE_HEADER = 'X-Nonce-Value'
NONCE_CREATED_AT_HEADER = 'X-Nonce-Created-At'


def sign(signature_input):
    print('signature_input', signature_input)
    signature_input_b64 = base64.standard_b64encode(signature_input.encode()).decode()
    print('signature_input_b64', signature_input_b64)

    cmd = """printf %s "{}" | openssl dgst -sha256 -sign {}| openssl base64""".format(signature_input_b64, PRIVATE_KEY)
    print(cmd)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    output, err = process.communicate()
    if err.decode() != "":
        raise Exception(err)

    return output.decode().replace("\n", "")

def sendingRequest(msg, initiator, helper):
    method = msg.getRequestHeader().getMethod() 
    path = urlparse.urlparse(msg.getRequestHeader().getURI().toString()).path
    body = msg.getRequestBody().toString()
    print(msg.getRequestBody().toString())

    nonce_value = str(uuid.uuid4())
    nonce_created_at = '{}+00:00'.format(datetime.datetime.utcnow().isoformat())
    signature = sign("{}{}{}{}{}".format(method, path, nonce_value, nonce_created_at, body))

    print('Adding new {}: {}'.format(SIGNATURE_HEADER, signature))
    msg.getRequestHeader().setHeader(SIGNATURE_HEADER, signature)

    print('Adding new {}: {}'.format(NONCE_HEADER, nonce_value))
    msg.getRequestHeader().setHeader(NONCE_HEADER, nonce_value)

    print('Adding new {}: {}'.format(NONCE_CREATED_AT_HEADER, nonce_created_at))
    msg.getRequestHeader().setHeader(NONCE_CREATED_AT_HEADER, nonce_created_at)


def responseReceived(msg, initiator, helper):
    pass

