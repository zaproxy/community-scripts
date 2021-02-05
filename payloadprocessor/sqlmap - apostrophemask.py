def process(payload):

    return payload.replace('\'', "%EF%BC%87") if payload else payload
