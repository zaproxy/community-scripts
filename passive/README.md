Passive Rule scripts
====================

These detect potential vulnerabilities by passively analysing traffic to and from the target, run as part of the Passive Scanner and can be individually enabled.

## JavaScript template

```JavaScript
// Passive scan rules should not make any requests 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

var PluginPassiveScanner = Java.type("org.zaproxy.zap.extension.pscan.PluginPassiveScanner");

/**
 * Passively scans an HTTP message. The scan function will be called for 
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 * 
 * @param ps - the PassiveScan parent object that will do all the core interface tasks 
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.). 
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */
function scan(ps, msg, src) {
	// Test the request and/or response here
	if (true) {	// Change to a test which detects the vulnerability
		// risk: 0: info, 1: low, 2: medium, 3: high
		// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
		ps.newAlert()
			.setRisk(1)
			.setConfidence(1)
			.setName('Passive Vulnerability title')
			.setDescription('Full description')
			.setParam('The param')
			.setEvidence('Evidence')
			.setOtherInfo('Any other info')
			.setSolution('The solution')
			.setReference('References')
			.setCweId(0)
			.setWascId(0)
			.raise();
		
		//addTag(String tag)
		ps.addTag('tag')			
	}
	
	// Raise less reliable alert (that is, prone to false positives) when in LOW alert threshold
	// Expected values: "LOW", "MEDIUM", "HIGH"
	if (ps.getAlertThreshold() == "LOW") {
		// ...
	}
}

/**
 * Tells whether or not the scanner applies to the given history type.
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether or not the message with the given type should be scanned by this scanner.
 */
function appliesToHistoryType(historyType) {
	// For example, to just scan spider messages:
	// return historyType == org.parosproxy.paros.model.HistoryReference.TYPE_SPIDER;

	// Default behaviour scans default types.
	return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| ps | [ScriptsPassiveScanner](https://static.javadoc.io/org.zaproxy/zap/2.9.0/org/zaproxy/zap/extension/pscan/scanner/ScriptsPassiveScanner.html) |
| msg | [HttpMessage](https://static.javadoc.io/org.zaproxy/zap/2.9.0/org/parosproxy/paros/network/HttpMessage.html) |
| source | [Source](http://jericho.htmlparser.net/docs/javadoc/net/htmlparser/jericho/Source.html) |
| historyType | int |

## Templates in other languages

* Groovy : [PassiveDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/main/addOns/groovy/src/main/zapHomeFiles/scripts/templates/passive/PassiveDefaultTemplate.groovy)
* Jruby : [Passive default template.rb](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jruby/src/main/zapHomeFiles/scripts/templates/passive/Passive%20default%20template.rb)
* Jython : [Passive default template.py](https://github.com/zaproxy/zap-extensions/blob/main/addOns/jython/src/main/zapHomeFiles/scripts/templates/passive/Passive%20default%20template.py)
* Zest : [Passive default template.zst](https://github.com/zaproxy/zap-extensions/blob/main/addOns/zest/src/main/zapHomeFiles/scripts/templates/passive/Passive%20default%20template.zst)

## Official Videos

[ZAP In Ten: Passive Scan Scripts](https://play.sonatype.com/watch/HfENJ3GJB3zbD6sMscDrjD) (11:55)
