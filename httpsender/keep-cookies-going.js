/*exported sendingRequest, responseReceived*/
// This script makes sure requests are always made with the auth cookies

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var ScriptVars    = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter')
var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

function sendingRequest(msg, initiator, helper) {
  var headers = msg.getRequestHeader();
  var cookies = headers.getCookieParams();

  // @todo prevent re-auth
  var key         = ScriptVars.getGlobalVar("sesh.key");
  var secret      = ScriptVars.getGlobalVar("sesh.secret");
  var cookieParam = new HtmlParameter(COOKIE_TYPE, key, secret);

  if (!cookies.isEmpty()) {
    var existing = cookies.first();
    cookies.remove(existing);
  }

  cookies.add(cookieParam);
  msg.getRequestHeader().setCookieParams(cookies);

  return true
}

// If a cookie was set, capture it
function responseReceived(msg, initiator, helper) {
  var resheaders = msg.getResponseHeader();
  var setCookie  = resheaders.getHeader('Set-Cookie');

  if (setCookie === null) {return;}

  // @todo there can be multiple set cookies?
  var cookie        = setCookie.toString();
  var sessionInfo   = cookie.split(';')[0].split('=');
  var key           = sessionInfo[0];
  var secret        = sessionInfo[1];
  var isValidSecret = (secret && secret.length > 1);

  if  (!isValidSecret) {return;}

  logger("Captured set cookie of " +  key + " " + secret);

  ScriptVars.setGlobalVar("sesh.key", key);
  ScriptVars.setGlobalVar("sesh.secret", secret);
  // @todo set active session
}
