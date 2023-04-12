/*
This is part of a set of scripts which allow you to authenticate to Juice Shop using Selenium.

These scripts will currently only run in Oracle Nashorn and not Graal.js 
which means you need to run ZAP using Java 11.

---

This script stops the proxy used for authentication and removes all of the script variables.
It is not needed for automation but can be useful for manual testing.
*/

function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

var proxy = ScriptVars.getGlobalCustomVar("auth-proxy");

if (proxy) {
	logger("Found auth proxy - stopping");
	proxy.stop();
	ScriptVars.setGlobalCustomVar("auth-proxy", null);
}

var token = ScriptVars.getGlobalVar("juiceshop.token");
if (token) {
	logger("Found token - removing");
	ScriptVars.setGlobalVar("juiceshop.token", null);

}

// Reset the state for all users
var extUser = control.getExtensionLoader().getExtension(
		org.zaproxy.zap.extension.users.ExtensionUserManagement.class);
var session = model.getSession();
var contexts = session.getContexts();
for (i in contexts) {
	var users = extUser.getContextUserAuthManager(contexts[i].getId()).getUsers();
	for (j in users) {
		logger("Resetting user " + users[j]);
		users[j].getAuthenticationState().setLastPollResult(false);
	}
}

logger("Reset complete.");

