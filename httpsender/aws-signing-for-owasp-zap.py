# AWS Signing Script for OWASP Zed Attack Proxy - ZAP
# HelpAddOn Script - HTTPSender
# Ismael Goncalves - https://sharingsec.blogspot.com
# https://github.com/irgoncalves
#
# Tested with Jython 2.5.4 and ZAP 2.7.0
# For AWS Signing Process (aws4): https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
# Based On: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

import time, hashlib, hmac, urlparse, urllib

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

# access and secret key for AWS
access_key = 'myaccesskey'
secret_key = 'mysecretkey'
service = 'execute-api'
region = 'us-east-1'
   
# token for x-amz-security-token - leave blank if it is not necessary
# when used with temporary access/secret keys it must be sent
token = ''

amzdate = time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
datestamp = time.strftime('%Y%m%d',time.gmtime())

def sendingRequest(msg, initiator, helper): 

   parsedurl = urlparse.urlparse(msg.getRequestHeader().getURI().toString())
   canonical_uri = urllib.quote(parsedurl.path if parsedurl.path else '/', safe='/-_.~')
   method = msg.getRequestHeader().getMethod()   
   host = msg.getRequestHeader().getHostName()
   canonical_querystring = ''
   
   # replace any + * from ZAP Payloads with %20 - + breaks signature
   query = parsedurl.query.replace('+', '%20')
   query = query.replace('*', '%2A') 

   # sort parameters
  
   querystring_sorted = '&'.join(sorted(query.split('&')))
      
   if querystring_sorted != '':
      for query_param in querystring_sorted.split('&'):
         key_val_split = query_param.split('=', 1)
   
         key = key_val_split[0]
         if len(key_val_split) > 1:
            val = key_val_split[1]
         else:
            val = ''
         
         if key:
            if canonical_querystring:
               canonical_querystring += "&"
            canonical_querystring += u'='.join([key, val])
   

   canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
   signed_headers = 'host;x-amz-date'
   payload = msg.getRequestBody().toString();
   payload_hash = hashlib.sha256(payload).hexdigest()
   canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
   algorithm = 'AWS4-HMAC-SHA256'
   credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
   string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
   signing_key = getSignatureKey(secret_key, datestamp, region, service)
   signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
   authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
   
   headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}
   
   # check if token is necessary
   if token != '':
      headers.update({'x-amz-security-token':token})

   for x in list(headers):
      msg.getRequestHeader().setHeader(x, headers[x]);
   
def responseReceived(msg, initiator, helper): 
    pass;
