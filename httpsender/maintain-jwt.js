/*exported sendingRequest, responseReceived*/
// This script looks for JWT tokens in responses, the current one
// via ScriptVars, and updates all requests adding an Authorization header
// bearer value based on the tracked JWT.

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter");
var COOKIE_TYPE = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

function sendingRequest(msg, initiator, helper) {
  if (initiator === HttpSender.AUTHENTICATION_INITIATOR) {
    logger("Trying to auth");
    return;
  }

  var token = ScriptVars.getGlobalVar("jwt-token");
  if (!token) {
    return;
  }
  var cookie = new HtmlParameter(COOKIE_TYPE, "token", token);
  msg.getRequestHeader().getCookieParams().add(cookie);
  // For all non-authentication requests we want to include the authorization header
  logger("Added authorization token " + token.slice(0, 20) + " ... ");
  msg.getRequestHeader().setHeader("Authorization", "Bearer " + token);
}

function responseReceived(msg, initiator, helper) {
  var resbody = msg.getResponseBody().toString();
  var resheaders = msg.getResponseHeader();

  if (initiator !== HttpSender.AUTHENTICATION_INITIATOR) {
    var token = ScriptVars.getGlobalVar("jwt-token");
    if (!token) {
      return;
    }

    var headers = msg.getRequestHeader();
    var cookies = headers.getCookieParams();
    var cookie = new HtmlParameter(COOKIE_TYPE, "token", token);

    if (cookies.contains(cookie)) {
      return;
    }
    msg
      .getResponseHeader()
      .setHeader("Set-Cookie", "token=" + token + "; Path=/;");
    return;
  }

  logger("Handling auth response");
  if (resheaders.getStatusCode() > 299) {
    logger("Auth failed");
    return;
  }

  // Is response JSON? @todo check content-type
  if (resbody[0] !== "{") {
    return;
  }
  try {
    var data = JSON.parse(resbody);
  } catch (e) {
    return;
  }

  // If auth request was not succesful move on
  if (!data["authentication"]) {
    return;
  }

  // @todo abstract away to be configureable
  var token = data["authentication"]["token"];
  logger("Capturing token for JWT\n" + token);
  ScriptVars.setGlobalVar("jwt-token", token);
  msg
    .getResponseHeader()
    .setHeader("Set-Cookie", "token=" + token + "; Path=/;");
}
