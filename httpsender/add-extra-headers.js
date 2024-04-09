/*exported sendingRequest, responseReceived*/
// This script looks for headers other than those on the ignore list
// Adds them to a global variable then adds them to subsequent requests as they are sent.

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

var ignoreHeader = [
  "Connection",
  "Accept",
  "Origin",
  "Host",
  "Content-Type",
  "Content-Length",
  "Referer",
  "Cookie",
  "User-Agent", // @todo user-agent may be special?
  "Referer",
  "Accept-Language",
  "Access-Control-Request-Headers",
  "Access-Control-Request-Method",
  "Date",
  "Cache-Control",
  "Pragma",
  "Upgrade",
  "Via",
  "Upgrade-Insecure-Requests",
  "X-NewRelic-ID",
];

function sendingRequest(msg, initiator, helper) {
  if (initiator === HttpSender.AUTHENTICATION_INITIATOR) {
    logger("Trying to auth");
    return;
  }
  var hostname = msg.getRequestHeader().getHostName();
  var varKey = "headers-" + hostname;
  var extras = ScriptVars.getGlobalVar(varKey);
  var headers = msg.getRequestHeader().getHeaders();

  if (extras) {
    try {
      if (extras.length < 4) {
        extras = false;
      } else {
        extras = JSON.parse(extras);
        if (Object.keys(extras).length === 0) {
          extras = false;
        }
      }
    } catch (err) {
      logger(err);
      extras = false;
    }
  }

  if (!extras) {
    extras = {};
    for (var z in headers) {
      var header = headers[z];
      var name = header.getName();
      var val = header.getValue();
      if (~ignoreHeader.indexOf(name)) {
        continue;
      }
      logger("Found interesting header: " + name);
      extras[name] = val;
    }

    ScriptVars.setGlobalVar(varKey, JSON.stringify(extras));
  }

  for (var key in extras) {
    if (msg.getRequestHeader().getHeader(key)) {
      logger("Setting extra header - " + key + ": " + extras[key]);
      msg.getRequestHeader().setHeader(key, extras[key]);
    }
  }
}

function responseReceived(msg, initiator, helper) {}
