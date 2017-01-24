# The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP, 
# including automated tools (e.g. active scanner, fuzzer, ...)
# Note that new HttpSender scripts will initially be disabled
# Right click the script in the Scripts tree and select "enable"  
# 'initiator' is the component the initiated the request:
#      1   PROXY_INITIATOR
#      2   ACTIVE_SCANNER_INITIATOR
#      3   SPIDER_INITIATOR
#      4   FUZZER_INITIATOR
#      5   AUTHENTICATION_INITIATOR
#      6   MANUAL_REQUEST_INITIATOR
#      7   CHECK_FOR_UPDATES_INITIATOR
#      8   BEAN_SHELL_INITIATOR
#      9   ACCESS_CONTROL_SCANNER_INITIATOR
# For the latest list of values see the HttpSender class:
# https://github.com/zaproxy/zaproxy/blob/master/src/org/parosproxy/paros/network/HttpSender.java
# 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender 
# instance used to send the request.
#
# New requests can be made like this:
# msg2 = msg.cloneAll() # msg2 can then be safely changed as required without affecting msg
# helper.getHttpSender().sendAndReceive(msg2, false);
# println('msg2 response=' + msg2.getResponseHeader().getStatusCode())

#headers = dict({"X-MIP-ACCESS-TOKEN": "eda1fd8f-c398-4ae6-aa70-f3e043e2019a",
#                "X-MIP-CHANNEL": "ANDROID",
#                "X-MIP-Device-Id": "1",
#                "X-MIP-APP-VERSION": "1.0.1",
#                "X-MIP-APP-VERSION-ID": "1",
#            "X-Mcare-Proxy-Version": "1.0"});

headers2 = dict({"Content-Type": "text/plain"});

def sendingRequest(msg, initiator, helper): 
    # Debugging can be done using println like this
    #print('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
    pass;


def responseReceived(msg, initiator, helper): 
    # Debugging can be done using println like this
    #print('responseReceived called for url=' + msg.getRequestHeader().getURI().toString())
    for x in list(headers2):
      msg.getResponseHeader().setHeader(x, headers2[x]);


