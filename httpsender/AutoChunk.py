# This script will fix the data chunk format in the request body.
# Coded by: https://nmwafa.github.io - with GPT

def is_chunked(msg):
    te = msg.getRequestHeader().getHeader("Transfer-Encoding")
    return te and "chunked" in te.lower()

def fix_chunk_format(body):
    try:
        lines = body.replace("\r", "").split("\n")
        fixed = ""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line == "0":
                fixed += "0\r\n\r\n"
                break
            if line == "":
                i += 1
                continue
            try:
                chunk_len = int(line, 16)
            except:
                break
            i += 1
            if i >= len(lines):
                break
            chunk_data = lines[i]
            fixed += "%s\r\n%s\r\n" % (line, chunk_data)
            i += 1
        return fixed
    except Exception as e:
        return body  # fallback

def escape_crlf(text):
    return text.replace("\r", "\\r").replace("\n", "\\n")

def sendingRequest(msg, initiator, helper):
    try:
        if not is_chunked(msg):
            return

        original_body = msg.getRequestBody().toString()
        fixed_body = fix_chunk_format(original_body)

        # update
        if original_body != fixed_body:
            msg.setRequestBody(fixed_body)

    except Exception as e:
        print("[!] ERROR sendingRequest: %s" % str(e))

def responseReceived(msg, initiator, helper):
    pass
