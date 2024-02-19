# RSA Encrypt Payload Script for Zed Attack Proxy - ZAP
# HelpAddOn Script - HTTPSender
# Michal Walkowski - https://mwalkowski.github.io/
#
# Tested with Jython 14 beta and ZAP 2.14.0
# Based On: https://mwalkowski.github.io/post/using-burp-python-scripts-to-encrypt-requests-with-rsa-keys/
# You can test the script's functionality using https://github.com/mwalkowski/api-request-security-poc



import json
import base64
import subprocess

# path to public.pem
PUBLIC_KEY = "public.pem"

PAYLOAD_PLACEHOLDER = "PAYLOAD"
PAYLOAD = '{\"keyId\": \"init\", \"encryptedPayload\": \"' + PAYLOAD_PLACEHOLDER + '\"}'


def encrypt_body(body):
    body_b64 = base64.standard_b64encode(json.dumps(body, ensure_ascii=False).encode()).decode()

    cmd = 'printf %s "{}" | openssl pkeyutl -encrypt -pubin -inkey {} | openssl base64'.format(body_b64, PUBLIC_KEY)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, err = process.communicate()
    if err.decode() != "":
        raise Exception(err)

    return output.decode().replace("\n", "")


def sendingRequest(msg, initiator, helper):
    body = msg.getRequestBody().toString()
    msg.setNote(body)
    body = json.loads(body)
    encrypted_body = encrypt_body(body)
    new_payload = PAYLOAD.replace(PAYLOAD_PLACEHOLDER, encrypted_body)
    msg.setRequestBody(new_payload)
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length())


def responseReceived(msg, initiator, helper):
    body = msg.getNote()
    msg.setRequestBody(body)
