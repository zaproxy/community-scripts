Targeted scripts
================

Scripts that invoked with a target URL and are only run when your start them manually. 

## JavaScript template

```JavaScript
// Targeted scripts can only be invoked by you, the user, e.g. via a right-click option on the Sites or History tabs

/**
 * A function which will be invoked against a specific "targeted" message.
 *
 * @param msg - the HTTP message being acted upon. This is an HttpMessage object.
 */
function invokeWith(msg) {
	// Debugging can be done using println like this
	print('invokeWith called for url=' + msg.getRequestHeader().getURI().toString()); 
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| msg | [HttpMessage](https://static.javadoc.io/org.zaproxy/zap/2.9.0/org/parosproxy/paros/network/HttpMessage.html) |

## Templates in other languages

* Groovy : [TargetedDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/main/addOns/groovy/src/main/zapHomeFiles/scripts/templates/targeted/TargetedDefaultTemplate.groovy)
* Jruby : [Targeted default template.rb](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jruby/src/main/zapHomeFiles/scripts/templates/targeted/Targeted%20default%20template.rb)
* Jython : [Targeted default template.py](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jython/src/main/zapHomeFiles/scripts/templates/targeted/Targeted%20default%20template.py)
* Zest : [Targeted default template.zst](https://github.com/zaproxy/zap-extensions/blob/main/addOns/zest/src/main/zapHomeFiles/scripts/templates/targeted/Targeted%20default%20template.zst)

## Official Videos

[ZAP In Ten: Targeted Scripts](https://play.sonatype.com/watch/JzX1YkJqdk7BYTMHikh433) (10:01)
