Active Rule scripts
===================

These detect potential vulnerabilities by actively attacking the target, run as part of the Active Scanner and can be individually enabled.

## JavaScript template

```JavaScript
// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString());

	// Copy requests before reusing them
	msg = msg.cloneRequest();
	
	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	as.sendAndReceive(msg, false, false);

	// Test the responses and raise alerts as below

	// Check if the scan was stopped before performing lengthy tasks
	if (as.isStop()) {
		return
	}
	// Do lengthy task...
	
	// Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
	// Expected values: "LOW", "MEDIUM", "HIGH"
	if (as.getAlertThreshold() == "LOW") {
		// ...
	}
	
	// Do more tests in HIGH attack strength
	// Expected values: "LOW", "MEDIUM", "HIGH", "INSANE"
	if (as.getAttackStrength() == "HIGH") {
		// ...
	}
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
		' param=' + param + ' value=' + value);
	
	// Copy requests before reusing them
	msg = msg.cloneRequest();
	
	// setParam (message, parameterName, newValue)
	as.setParam(msg, param, 'Your attack');
	
	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	as.sendAndReceive(msg, false, false);
	
	// Test the response here, and make other requests as required
	if (true) {	// Change to a test which detects the vulnerability
		// risk: 0: info, 1: low, 2: medium, 3: high
		// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
		as.newAlert()
			.setRisk(1)
			.setConfidence(1)
			.setName('Active Vulnerability title')
			.setDescription('Full description')
			.setParam(param)
			.setAttack('Your attack')
			.setEvidence('Evidence')
			.setOtherInfo('Any other info')
			.setSolution('The solution')
			.setReference('References')
			.setCweId(0)
			.setWascId(0)
			.setMessage(msg)
			.raise();
	}
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| as | [ScriptsActiveScanner](https://static.javadoc.io/org.zaproxy/zap/latest/org/zaproxy/zap/extension/ascan/ScriptsActiveScanner.html) |
| msg | [HttpMessage](https://static.javadoc.io/org.zaproxy/zap/latest/org/parosproxy/paros/network/HttpMessage.html) |
| param | [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html) |
| value | [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html) |

## Templates in other languages

* Groovy : [ActiveDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/main/addOns/groovy/src/main/zapHomeFiles/scripts/templates/active/ActiveDefaultTemplate.groovy)
* Jruby : [Active default template.rb](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jruby/src/main/zapHomeFiles/scripts/templates/active/Active%20default%20template.rb)
* Jython : [Active default template.py](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jython/src/main/zapHomeFiles/scripts/templates/active/Active%20default%20template.py)
* Zest : [Active default template.zst](https://github.com/zaproxy/zap-extensions/blob/main/addOns/zest/src/main/zapHomeFiles/scripts/templates/active/Active%20default%20template.zst)


## Official Videos

[ZAP In Ten: Active Scan Scripts](https://play.sonatype.com/watch/aEwqErXFMTYdDDQbTgnJeA) (11:38)
