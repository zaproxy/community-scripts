// This script will log a browser into Juice Shop when forced user mode is enabled.
// The 'Juice Shop Session Management.js' script must have been set to authenticate correctly.
// Make sure to use the version of that script in this repo rather than the one included with ZAP 2.9.0 as
// it has been enhanced to support this script.

var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
//Change the jsUrl var if the instance of Juice Shop you are using is not listening on http://localhost:3000
var jsUrl = "http://localhost:3000";

function browserLaunched(ssutils) {
  var token = ScriptVars.getGlobalVar("juiceshop.token");
  if (token != null) {
    logger("browserLaunched " + ssutils.getBrowserId());
    var wd = ssutils.getWebDriver();
    var url = ssutils.waitForURL(5000);
    if (url.startsWith(jsUrl)) {
      logger("url: " + url + " setting token " + token);
      var script =
        "document.cookie = 'token=" +
        token +
        "';\n" +
        "window.localStorage.setItem('token', '" +
        token +
        "');";
      wd.executeScript(script);
    }
  } else {
    logger("no token defined");
  }
}

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}
