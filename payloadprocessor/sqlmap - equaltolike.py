import re

def process(payload):

    retVal = payload

    if payload:
        retVal = re.sub(r"\s*=\s*", " LIKE ", retVal)

    return retVal
