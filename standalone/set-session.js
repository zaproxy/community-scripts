// If you have a script (eg ZEST) that authenticates and you need to 
// set the active session to the new one just set, invoke this script
if (typeof println == 'undefined') this.println = print;

var URL                   = Java.type('java.net.URL');
var Control               = Java.type('org.parosproxy.paros.control.Control');
var View                  = Java.type('org.parosproxy.paros.view.View');
var ExtensionHttpSessions = Java.type('org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions')
var HttpSession           = Java.type('org.zaproxy.zap.extension.httpsessions.HttpSession');
var HttpSessionTokensSet  = Java.type('org.zaproxy.zap.extension.httpsessions.HttpSessionTokensSet');

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);

  // Logs to Output panel, useful for when triggered by other scripts
  View.getSingleton().getOutputPanel().appendAsync('[set-session] ' + arguments[0] + "\n");
}

function setActiveSession() {
  // If the script is called directly without params it should stop
  try {
    if (!sessid) {return false;}
  } catch(e) {
    logger("No ssessid set \n");
    return false;
  }
  
  var url = new URL(site)
  var port = url.getPort() > 0 ? url.getPort() : 80;

  if (url.getPort() === -1 && url.getProtocol() === 'https') {
    port = 443;
  }
  
  var sitePort = url.getHost() + ":" + port;
  var domain = url.getHost();
  var tmp = sessid.split('=');
  var sessionToken = tmp[1];
  var sessionLabel = tmp[0];
  
  logger("Trying to setup session for " + sitePort)

  var extension = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHttpSessions.class)
  var siteSessions = extension.getHttpSessionsSite(sitePort)
  var sessions = siteSessions.getHttpSessions().toArray()

  logger("Looking for " + sessionLabel + " with " + sessionToken);

  for (var i in sessions) {
    var sesh   = sessions[i];
	var ftoken = sesh.getTokenValue(sessionLabel);

    if (ftoken === sessionToken) {
      logger("Session set to existing " + sessid);
      siteSessions.setActiveSession(sesh);
      return sesh;
    }
  }
  
  logger("New session created")
  siteSessions.createEmptySession();
  var sesh   = siteSessions.getActiveSession();
  var cookie = new org.apache.commons.httpclient.Cookie(domain, sessionLabel, sessionToken);
  sesh.setTokenValue(sessionLabel, cookie);
  siteSessions.setActiveSession(sesh)
  return sesh;
}

var sesh = setActiveSession() || {name: ''};

// The last line is evaluated and assigned to variable for chaining scripts
sesh.name;

