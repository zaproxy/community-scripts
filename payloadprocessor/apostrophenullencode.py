def process(payload):
    # Do some processing to payload
    processed_payload = payload.replace("'", "%00%27");
    return processed_payload;

