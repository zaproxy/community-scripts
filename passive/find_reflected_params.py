"""
looks for parameter values that are reflected in the response.
Author: maradrianbelen.com
The scan function will be called for request/response made via ZAP, excluding some of the automated tools
Passive scan rules should not make any requests 
Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"

Refactored & Improved by nil0x42
"""

# Set to True if you want to see results on a per param basis
#  (i.e.: A single URL may be listed more than once)
RESULT_PER_FINDING = False

# Ignore parameters whose length is too short
MIN_PARAM_VALUE_LENGTH = 8


def scan(ps, msg, src): 
    # Docs on alert raising function:
    #  raiseAlert(int risk, int confidence, str name, str description, str uri,
    #               str param, str attack, str otherInfo, str solution,
    # 		   str evidence, int cweId, int wascId, HttpMessage msg)
    #  risk: 0: info, 1: low, 2: medium, 3: high
    #  confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    alert_title = "Reflected HTTP GET parameter(s) (script)"
    alert_desc = ("Reflected parameter value has been found. "
                  "A reflected parameter values may introduce XSS "
                  "vulnerability or HTTP header injection.")

    uri = header = body = None
    reflected_params = []

    for param in msg.getUrlParams():
        value = param.getValue()
        if len(value) < MIN_PARAM_VALUE_LENGTH:
            continue

        if not header:
            uri = msg.getRequestHeader().getURI().toString()
            header = msg.getResponseHeader().toString()
            body = msg.getResponseBody().toString()

        if value in header or value in body:
            if RESULT_PER_FINDING:
                param_name = param.getName()
                ps.raiseAlert(0, 2, alert_title, alert_desc, uri, param_name,
                        None, None, None, value, 0, 0, msg)
            else:
                reflected_params.append(param.getName())

    if reflected_params and not RESULT_PER_FINDING:
        reflected_params = u",".join(reflected_params)
        ps.raiseAlert(0, 2, alert_title, alert_desc, uri, reflected_params,
                None, None, None, None, 0, 0, msg)
