# @author RUFFENACH timothée
# Version 1.0
# encode payload to full HTML encode

def process(payload):
	payloadEncode=""

	# convert to full HTML
	for i in payload:
		payloadEncode += "&#"
		payloadEncode += str(ord(i))
		payloadEncode += ";"

	return payloadEncode
