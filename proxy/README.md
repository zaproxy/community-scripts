Proxy scripts
=============

Scripts which these run 'inline', can change every request and response that is proxied through ZAP and can be individually enabled. 
They can also trigger break points. 
They are not invoked for requests that originate from ZAP, for example from the active scanner or spiders.
To access requests that originate from ZAP use httpsender scripts.

## Javascript template

```javascript
// The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP, 
// excluding some of the automated tools
// If they return 'false' then the corresponding request / response will be dropped. 
// You can use msg.setForceIntercept(true) in either method to force a break point

// Note that new proxy scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

/**
 * This function allows interaction with proxy requests (i.e.: outbound from the browser/client to the server).
 * 
 * @param msg - the HTTP request being proxied. This is an HttpMessage object.
 */
function proxyRequest(msg) {
	// Debugging can be done using print like this
	print('proxyRequest called for url=' + msg.getRequestHeader().getURI().toString())
	
	return true
}

/**
 * This function allows interaction with proxy responses (i.e.: inbound from the server to the browser/client).
 * 
 * @param msg - the HTTP response being proxied. This is an HttpMessage object.
 */
function proxyResponse(msg) {
	// Debugging can be done using print like this
	print('proxyResponse called for url=' + msg.getRequestHeader().getURI().toString())
	return true
}
```
## Variables
| Name | Javadocs |
| --- | --- |
| msg | [HttpMessage](https://static.javadoc.io/org.zaproxy/zap/2.8.0/org/parosproxy/paros/network/HttpMessage.html) |

## Code Links
* [ProxyScript.java](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/zaproxy/zap/extension/script/ProxyScript.java)

## Templates in other languages

* Groovy : [ProxyDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/main/addOns/groovy/src/main/zapHomeFiles/scripts/templates/proxy/ProxyDefaultTemplate.groovy)
* Jruby : [Proxy default template.rb](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jruby/src/main/zapHomeFiles/scripts/templates/proxy/Proxy%20default%20template.rb)
* Jython : [Proxy default template.py](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jython/src/main/zapHomeFiles/scripts/templates/proxy/Proxy%20default%20template.py)
* Zest : [Proxy default template.zst](https://github.com/zaproxy/zap-extensions/blob/main/addOns/zest/src/main/zapHomeFiles/scripts/templates/proxy/Proxy%20default%20template.zst)


## Official Videos

[ZAP In Ten: Proxy and HttpSender Scripts](https://play.sonatype.com/watch/4no8EY1iB8RdnQLPFpYi2a) (10:14)

