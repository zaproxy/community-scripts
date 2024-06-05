"""
looks for parameter values that are reflected in the response.
Author: maradrianbelen.com
The scan function will be called for request/response made via ZAP, excluding some of the automated tools
Passive scan rules should not make any requests 
Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"

Refactored & Improved by nil0x42
"""

from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

# Set to True if you want to see results on a per param basis
#  (i.e.: A single URL may be listed more than once)
RESULT_PER_FINDING = False

# Ignore parameters whose length is too short
MIN_PARAM_VALUE_LENGTH = 8


def getMetadata():
    return ScanRuleMetadata.fromYaml("""
id: 100014
name: Reflected HTTP GET Parameter(s)
description: >
    A reflected parameter value has been found in the HTTP response.
    Reflected parameter values may introduce XSS vulnerability or HTTP header injection.
risk: info
confidence: medium
cweId: 79  # CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
wascId: 8  # WASC-8: Cross-site Scripting (XSS)
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/find_reflected_params.py
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
""")


def scan(helper, msg, src):
    header = body = None
    reflected_params = []

    for param in msg.getUrlParams():
        value = param.getValue()
        if len(value) < MIN_PARAM_VALUE_LENGTH:
            continue

        if not header:
            header = msg.getResponseHeader().toString()
            body = msg.getResponseBody().toString()

        if value in header or value in body:
            if RESULT_PER_FINDING:
                helper.newAlert().setParam(param.getName()).setEvidence(value).setMessage(msg).raise()
            else:
                reflected_params.append(param.getName())

    if reflected_params and not RESULT_PER_FINDING:
        other_info = 'Other instances: ' + u",".join(reflected_params[1:])
        helper.newAlert().setParam(param.getName()).setEvidence(reflected_params[0]).setOtherInfo(
            other_info).setMessage(msg).raise()
