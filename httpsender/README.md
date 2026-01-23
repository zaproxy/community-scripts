HTTP Sender scripts
===================

Scripts which these run 'inline', can change every request and response and can be individually enabled. 
They are invoked for proxied requests and requests that originate from ZAP, for example from the active scanner or spiders.

## Javascript template

```javascript
// The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP, 
// including automated tools (e.g. active scanner, fuzzer, ...)

// Note that new HttpSender scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// 'initiator' is the component that initiated the request.
// For the latest list of values see the "Request Initiator" entries in the constants documentation:
// https://www.zaproxy.org/docs/constants/
// 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender 
// instance used to send the request.
//
// New requests can be made like this:
// msg2 = msg.cloneAll() // msg2 can then be safely changed as required without affecting msg
// helper.getHttpSender().sendAndReceive(msg2, false);
// print('msg2 response=' + msg2.getResponseHeader().getStatusCode())

function sendingRequest(msg, initiator, helper) {
	// Debugging can be done using print like this
	print('sendingRequest called for url=' + msg.getRequestHeader().getURI().toString())
}

function responseReceived(msg, initiator, helper) {
	// Debugging can be done using print like this
	print('responseReceived called for url=' + msg.getRequestHeader().getURI().toString())
}
```
## Variables
| Name | Javadocs |
| --- | --- |
| msg | [HttpMessage](https://static.javadoc.io/org.zaproxy/zap/latest/org/parosproxy/paros/network/HttpMessage.html) |
| initiator | int |
| helper | [HttpSenderScriptHelper](https://static.javadoc.io/org.zaproxy/zap/latest/org/zaproxy/zap/extension/script/HttpSenderScriptHelper.html) |

## Code Links
* [HttpSenderScript.java](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/zaproxy/zap/extension/script/HttpSenderScript.java)
* [HttpSender.java](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/parosproxy/paros/network/HttpSender.java)

## Template in other languages

* Groovy : [HttpSenderDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/main/addOns/groovy/src/main/zapHomeFiles/scripts/templates/httpsender/HttpSenderDefaultTemplate.groovy)
* Jruby : [HttpSender default template.rb](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jruby/src/main/zapHomeFiles/scripts/templates/httpsender/HttpSender%20default%20template.rb)
* Jython : [HttpSender default template.py](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jython/src/main/zapHomeFiles/scripts/templates/httpsender/HttpSender%20default%20template.py)
* Zest : [HttpSender default template.zst](https://github.com/zaproxy/zap-extensions/blob/main/addOns/zest/src/main/zapHomeFiles/scripts/templates/httpsender/HttpSender%20default%20template.zst)

