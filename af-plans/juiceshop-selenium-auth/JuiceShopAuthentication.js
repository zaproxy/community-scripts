/*
This is part of a set of scripts which allow you to authenticate to Juice Shop using Selenium.

These scripts will currently only run in Oracle Nashorn and not Graal.js 
which means you need to run ZAP using Java 11.

---

This script handles authentication for requests that originate from ZAP,
e.g. from the traditional spider or the active scanner.

It launches a browser to authenticate to Juice Shop - this is not strictly 
necessary but this is a demonstration of what to do if you need authenticate
via a browser.

It also starts and uses a new proxy on a different port.
If this is not done then the script will hang as it will try to authenticate 
again using the script which is already running.

The proxy can be stopped via the JuiceShopReset script.
*/

var By = Java.type('org.openqa.selenium.By');
var Cookie = Java.type("org.openqa.selenium.Cookie");
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpResponseHeader = Java.type("org.parosproxy.paros.network.HttpResponseHeader");
var HttpHeader = Java.type('org.parosproxy.paros.network.HttpHeader');
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var System = Java.type("java.lang.System");
var Thread = Java.type('java.lang.Thread');
var URI = Java.type('org.apache.commons.httpclient.URI');

var extensionNetwork = control.getExtensionLoader().getExtension("ExtensionNetwork");

var juiceshopAddr = "http://localhost:3000/";
var proxyAddress = "127.0.0.1";
var proxyPort = 9092;

var count = 0;
var limit = 2;

function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

function messageHandler(ctx, msg) {
	if (ctx.isFromClient()) {
		return;
	}
	var url = msg.getRequestHeader().getURI().toString();
	//logger("messageHandler " + url);
	if (url === juiceshopAddr + "rest/user/login" && msg.getRequestHeader().getMethod() === "POST") {
		var json = JSON.parse(msg.getResponseBody().toString());
		var token = json.authentication.token;
		logger("Saving Juice Shop token");
		// save the authentication token
		ScriptVars.setGlobalVar("juiceshop.token", token);
	}
}

function authenticate(helper, _paramsValues, _credentials) {
	// Remove an existing token (if present) - in theory it may now be invalid
	ScriptVars.setGlobalVar("juiceshop.token", null);
	var proxy = ScriptVars.getGlobalCustomVar("auth-proxy");
	if (!proxy) {
		// We need to start a new proxy so that the request doesn't trigger another login sequence
		logger("Starting proxy");
		var proxy = extensionNetwork.createHttpProxy(5, messageHandler);
		proxy.start(proxyAddress, proxyPort);
		// Store the proxy in a global script var
		ScriptVars.setGlobalCustomVar("auth-proxy", proxy);
	}

	logger("Launching browser to authenticate to Juice Shop");
	var extSel = control.getSingleton().
		getExtensionLoader().getExtension(
			org.zaproxy.zap.extension.selenium.ExtensionSelenium.class);

	// Change to "firefox" (or "chrome") to see the browsers being launched
	var wd = extSel.getWebDriver(5, "firefox-headless", proxyAddress, proxyPort);
	logger("Got webdriver");

	// Initial request will display a popup that is difficult to get rid of
	wd.get(juiceshopAddr);
	wd.manage().addCookie(new Cookie('cookieconsent_status', 'dismiss'));
	wd.manage().addCookie(new Cookie('welcomebanner_status', 'dismiss'));
	Thread.sleep(1000);
	// This request will get the login page without the pesky popup
	logger("Requesting login page");
	wd.get(juiceshopAddr + "#/login");
	Thread.sleep(1000);

	// These are standard selenium methods for filling out fields
	// You will need to change them to support different apps
	wd.findElement(By.id("email")).sendKeys(System.getenv("JS_USER"));
	wd.findElement(By.id("password")).sendKeys(System.getenv("JS_PWD"));
	wd.findElement(By.id("loginButton")).click();
	logger("Submitting form");

	Thread.sleep(500);
	wd.quit();

	Thread.sleep(500);
	logger("Checking verification URL for Juice Shop");
	token = ScriptVars.getGlobalVar("juiceshop.token");

	// This is the verification URL
	var requestUri = new URI(juiceshopAddr + "rest/user/whoami", false);
	var requestMethod = HttpRequestHeader.GET;
	var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
	// The auth token and cookie will be added by the httpsender script
	var msg = helper.prepareMessage();
	msg.setRequestHeader(requestHeader);
	helper.sendAndReceive(msg);

	return msg;
}

function getRequiredParamsNames() {
	return [];
}

function getOptionalParamsNames() {
	return [];
}

function getCredentialsParamsNames() {
	return ["username", "password"];
}

