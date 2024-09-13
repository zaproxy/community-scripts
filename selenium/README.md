Selenium scripts are called whenever a browser is launched from ZAP using selenium, for example for the Ajax Spider or for manual browsing. 
	
They have access to the launched browser and can interact with it, for example, run JavaScript scripts, access URLs, fill in forms, click buttons, add data to localStarage and sessionStorage ...

## JavaScript template

```JavaScript
/* The browserLaunched function is called whenever a browser is launched from ZAP using selenium.
	The util parameter has the following methods:
		getWebDriver() Returns the WebDriver: 
			https://www.javadoc.io/doc/org.seleniumhq.selenium/selenium-api/3.141.0/org/openqa/selenium/WebDriver.html 
		getRequester() Returns the identifier of the requester.
			For the latest list of values see the "Request Initiator" entries in the constants documentation:
			https://www.zaproxy.org/docs/constants/
		getBrowserId() Returns the browser Id, eg "firefox" or "chrome"
		getProxyAddress() Returns the address of the proxy
		getProxyPort() Returns the port of the proxy
		waitForUrl(timeoutInMsecs) Returns the current URL (once loaded) - waits up to timeoutInMsecs
*/
function browserLaunched(utils) {
	var url = utils.waitForURL(5000);
	logger('browserLaunched ' + utils.getBrowserId() + ' url: ' + url);
}

// Logging with the script name is super helpful!
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| utils | SeleniumScriptUtils.java - no JavaDocs, see code link |

## Code Links
* [SeleniumScript.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/selenium/src/main/java/org/zaproxy/zap/extension/selenium/SeleniumScript.java)
* [SeleniumScriptUtils.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/selenium/src/main/java/org/zaproxy/zap/extension/selenium/SeleniumScriptUtils.java)
