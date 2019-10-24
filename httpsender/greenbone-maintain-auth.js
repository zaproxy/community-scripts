/*exported sendingRequest, responseReceived*/
// Greenbone auth & sessions are a bit flaky with scans ...
// ... this helps make auth less flaky

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

function isStaticUrl(url) {
  if (url.indexOf('.xml') !== -1) {
    return true;
  }

  if (url.indexOf('.css') !== -1) {
    return true;
  }

  if (url.indexOf('.gif') !== -1) {
    return true;
  }

  if (url.indexOf('.js') !== -1) {
    return true;
  }

  if (url.indexOf('.txt') !== -1) {
    return true;
  }

  if (url.indexOf('.htm') !== -1) {
    return true;
  }
  return false;
}

var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;
var ScriptVars    = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var HttpSender    = Java.type('org.parosproxy.paros.network.HttpSender');

// Rewrite requests to include correct query token param
function sendingRequest(msg, initiator, helper) {
  var reqbody = msg.getRequestBody().toString();
  var headers = msg.getRequestHeader();
  var url     = headers.getURI().toString();
  var qry     = headers.getURI().getQuery();
  var cookies = headers.getCookieParams();

  if (initiator === HttpSender.SPIDER_INITIATOR) {}
  if (isStaticUrl(url)) {return;}

  var token   = ScriptVars.getGlobalVar("openvas.token")
  var gsad_id = ScriptVars.getGlobalVar("openvas.gsad_id")

  if (gsad_id === null || gsad_id === '0' || gsad_id == 0) {
    logger('No valid gsad_id')
    return;
  }

  if (token === null) {return;}

  // Already logged in, so move on
  if ((headers.getMethod() === 'POST' && reqbody.indexOf('cmd=login') !== -1) || url.indexOf('login') !== -1) {
    return;
  }

  var cookieParam = new HtmlParameter(COOKIE_TYPE, 'GSAD_SID', gsad_id);

  // https://hc.apache.org/httpclient-3.x/apidocs/org/apache/commons/httpclient/URI.html
  if (qry !== null && qry.toString().indexOf(token) !== -1) {
    logger('Already has token, no need to rewrite')
    return;
  }

  // If already a cookie, remove to reset
  if (!cookies.isEmpty()) {
    var existing = cookies.first()
    cookies.remove(existing)
  }

  cookies.add(cookieParam)
  msg.getRequestHeader().setCookieParams(cookies)

  var newqry = "token=" + token;

  if (qry !== null) {
    newqry = qry.replace(/[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}/, token);
  }

  // @todo add token to post data
  headers.getURI().setQuery(newqry)
}

// Monitor responses to look for successful login to update session info
function responseReceived(msg, initiator, helper) {
  var reqbody    = msg.getRequestBody().toString();
  var resbody    = msg.getResponseBody().toString()
  var headers    = msg.getRequestHeader();
  var resheaders = msg.getResponseHeader();

  // Login is only via POST
  if (headers.getMethod() !== 'POST') {return;}

  // Login has specific items in post body
  if (reqbody.indexOf('cmd=login') === -1) {return;}

  var cookie   = resheaders.getHeader('Set-Cookie').toString();
  var gsad_id  = cookie.split(';')[0].split('=')[1]
  var tokenIdx = resbody.indexOf("&token=")
  var token    = resbody.substring(tokenIdx + 7, tokenIdx + 43);

  // Ignore bad session id
  if (gsad_id == '0') {return;}

  ScriptVars.setGlobalVar("openvas.token", token)
  ScriptVars.setGlobalVar("openvas.gsad_id", gsad_id)

  logger("New greenbone session tokens " + token + " - " + gsad_id )
  // @todo set active session
}
