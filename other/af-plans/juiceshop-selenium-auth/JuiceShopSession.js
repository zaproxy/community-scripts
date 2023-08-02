/*
This is part of a set of scripts which allow you to authenticate to Juice Shop using Selenium.

These scripts will currently only run in Oracle Nashorn and not Graal.js 
which means you need to run ZAP using Java 11.

---

This script injects the authentication token into authenticated requests
from ZAP.

It is used by the traditional spider and the active scan rules 
(apart from the DOM XSS one which uses a browser).
It is not used by the AJAX Spider as that need the client side state to be set.

*/

function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var COOKIE_TYPE = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var Stats = Java.type('org.zaproxy.zap.utils.Stats');

function extractWebSession(_sessionWrapper) {
	// Handled in the auth script
}

function clearWebSessionIdentifiers(sessionWrapper) {
	var headers = sessionWrapper.getHttpMessage().getRequestHeader();
	headers.setHeader("Authorization", null);
	ScriptVars.setGlobalVar("juiceshop.token", null);
}

function processMessageToMatchSession(sessionWrapper) {
	var token = ScriptVars.getGlobalVar("juiceshop.token");
	if (token === null) {
		logger('no token');
		return;
	}
	var cookie = new HtmlParameter(COOKIE_TYPE, "token", token);
	// add the saved authentication token as an Authentication header and a cookie
	var msg = sessionWrapper.getHttpMessage();
	msg.getRequestHeader().setHeader("Authorization", "Bearer " + token);
	var cookies = msg.getRequestHeader().getCookieParams();
	cookies.add(cookie);
	msg.getRequestHeader().setCookieParams(cookies);
	Stats.incCounter("stats.juiceshop.tokens.added");
}

function getRequiredParamsNames() {
	return [];
}

function getOptionalParamsNames() {
	return [];
}
