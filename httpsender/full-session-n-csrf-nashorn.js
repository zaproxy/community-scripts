/**
 * @author D-36O at 0u7100k (c0m)
 * @since 17/02/2021
 * @summary Session and csrf management without auth/session scripts (nashorn compatible).
 *
 * Copyright 2021 Diego Díaz Morales
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var Source = Java.type("net.htmlparser.jericho.Source");
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader"
);
var HttpRequestBody = Java.type("org.zaproxy.zap.network.HttpRequestBody");
var URI = Java.type("org.apache.commons.httpclient.URI");
var HttpCookie = Java.type("java.net.HttpCookie");
var Thread = Java.type("java.lang.Thread");
var Void = Java.type("java.lang.Void");
var Byte = Java.type("java.lang.Byte");
var Short = Java.type("java.lang.Short");

var HTTP_VERSION = "HTTP/1.1";
var DATA_CHARSET = "UTF-8";
var DATA_KEY = "4956049A7";
var CSRF_KEY = "csrf";
var SESSION_KEY = "session";

var AUTH_INTERNALL_ERR_DELAY = 10000; // millis
var AUTH_INTERNALL_RETRIES = 3;
var AUTH_RETRIES = 0;
var CSRF_RETRIES = 0;
var RETRIES_ON_IO_ERROR = 1;

var DO_LOG = true;
var SYNC_LOG = false;
var SET_USE_GLOBAL_STATE = false;
var SET_USE_COOKIES = false;

// MOFIFY THIS LINES ACCORDING TO YOUR TARGET
var HOST = "localhost";
var USERNAME = "admin";
var PASSWORD = "password";
var SESSION_COOKIE_NAME = "PHPSESSID";
var CSRF_PARAM_NAME = "user_token";
var CSRF_HEADER_NAME = "X-CSRF-TOKEN";
var LOGIN_DATA =
  "username=" + USERNAME + "&password=" + PASSWORD + "&Login=Login&user_token=";
var UNAUTH_LOCATION = "http://" + HOST + "/login.php";
var PRE_AUTH_GET = "http://" + HOST + "/login.php";
var AUTH_POST = "http://" + HOST + "/login.php";
var CSRF_GET = "http://" + HOST + "/login.php";
var CSRF_PER_REQUEST = true;

function ID() {
  return Thread.currentThread().getId();
}
function AuthInfo(session, csrf) {
  this.session = session;
  this.csrf = csrf;
  this.id = ID();
  this.toString = function () {
    return (
      "{ id: " +
      this.id +
      ", session: " +
      this.session +
      ", csrf: " +
      this.csrf +
      " }"
    );
  };
}
function AuthPool(name) {
  this.sessions = [];
  this.name = name;
  this.lock = Java.synchronized(function (e) {
    e.id = ID();
  });
  this.unlock = Java.synchronized(function (e) {
    e.id = null;
  });
  this.toJson = function () {
    return JSON.stringify(this.sessions);
  };
  this.toString = function () {
    return this.name + ": " + JSON.stringify(this.sessions);
  };
  this.pushSession = function (authInfo) {
    this.sessions.push(authInfo);
    return this;
  };
  this.pollSession = function () {
    var e = find(this.sessions, function (e) {
      return !e.id;
    });
    if (e) this.lock(e);
    return e;
  };
  this.recoverSession = function () {
    return find(this.sessions, function (e) {
      return e.id == ID();
    });
  };
  this.releaseSession = function () {
    var e = find(this.sessions, function (e) {
      return e.id == ID();
    });
    if (e) this.unlock(e);
    return this;
  };
  this.invalidateSession = function () {
    for (var i in this) {
      if (this[i]["th"] == ID()) {
        this.splice(i, 1);
        return;
      }
    }
  };
}
var authPool = new AuthPool(DATA_KEY);

function skipInitiator(initiator) {
  switch (initiator) {
    case HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR:
      return true;
    case HttpSender.AUTHENTICATION_INITIATOR:
      return true;
    case HttpSender.BEAN_SHELL_INITIATOR:
      return true;
    case HttpSender.PROXY_INITIATOR:
      return true;
    default:
      return false;
  }
}

var doInit = Java.synchronized(function (helper) {
  var httpSender = helper.getHttpSender();
  httpSender.setUseGlobalState(SET_USE_GLOBAL_STATE);
  httpSender.setUseCookies(SET_USE_COOKIES);
  httpSender.setMaxRetriesOnIOError(RETRIES_ON_IO_ERROR);
  doInit = function () {};
}, Short.TYPE);

function doSkip(msg, initiator, caller) {
  var initiatorName = parseInitiator(initiator);
  var path = msg.getRequestHeader().getURI().getPath();
  var skip = skipInitiator(initiator);

  log(
    "{ method: doSkip { from: " +
      caller +
      " }" +
      ", initiator: " +
      initiatorName +
      ", path: " +
      path +
      ", skip: " +
      skip +
      " }"
  );

  return skip;
}

/**
 * @param msg will be modified (not cloned).
 */
function doRequest(msg, helper, follow_redirects, retries, note) {
  var requestHeader = msg.getRequestHeader();
  var httpSender = helper.getHttpSender();

  msg.setNote(note);

  try {
    httpSender.sendAndReceive(msg, follow_redirects);
  } catch (e) {
    log("{ method: doRequest { " + requestHeader.getPrimeHeader() + " }", true);
    log("{ method: doRequest { exception: " + e + " }", true);
    return null;
  }
  return msg;
}

function sendingRequest(msg, initiator, helper) {
  if (doSkip(msg, initiator, "sendingRequest")) {
    return;
  }

  doInit(helper);

  var requestHeader = msg.getRequestHeader();
  var requestBody = msg.getRequestBody();
  var authInfo = authPool.pollSession();

  if (!authInfo) {
    log("{ method: sendingRequest, no-auth-info: triggering auth process... }");
    authInfo = doAuth(helper);
    if (authInfo) authPool.pushSession(authInfo);
    else return;
  }

  if (CSRF_PER_REQUEST || (!authInfo.csrf && isCSRFRequired(msg))) {
    authInfo.csrf = getCSRF(msg, authInfo.session, helper);
  }

  replaceAuthInfo(msg, authInfo);

  requestHeader.setContentLength(requestBody.length());

  log("{ method: sendingRequest, auth-pool: " + authPool + " }");
  log(
    "{ method: sendingRequest (out), path: " +
      msg.getRequestHeader().getPrimeHeader() +
      " }"
  );
}

function responseReceived(msg, initiator, helper) {
  var responseHeader = msg.getResponseHeader();
  var httpSession = msg.getHttpSession();
  var r_code = responseHeader.getStatusCode();

  log(
    "{ method: responseReceived (" +
      procRC(responseHeader, r_code) +
      "), auth-pool: " +
      authPool +
      " }"
  );

  if (doSkip(msg, initiator, "responseReceived")) {
    return;
  }

  var authInfo;

  if (invalidationLogic(responseHeader, httpSession, r_code)) {
    authPool.invalidateSession();
    log(
      "{ method: responseReceived (session-invalidated), auth-pool: " +
        authPool +
        " }"
    );
    authInfo = doAuth(helper);
    if (authInfo) authPool.pushSession(authInfo);
  } else authInfo = authPool.recoverSession();

  authPool.releaseSession();

  log("{ method: responseReceived (out), auth-info: " + authInfo + " }");
}

/**
 * @param msg: final (cloned)
 */
function buildFromMessage(
  msg,
  version,
  secure,
  uri,
  escaped,
  method,
  data,
  charset,
  encode,
  content_type,
  cookies,
  user_agent
) {
  var request = msg.cloneRequest();
  var header = request.getRequestHeader();
  if (data) {
    var body = new HttpRequestBody();
    if (charset) body.setCharset(charset);
    body.setBody(encode === true ? encodeURIComponent(data) : data);
    request.setRequestBody(body);
    header.setContentLength(request.getRequestBody().length());
    if (
      content_type &&
      (HttpRequestHeader.POST.equals(method) ||
        HttpRequestHeader.PUT.equals(method))
    ) {
      header.setHeader(HttpHeader.CONTENT_TYPE, content_type);
    }
  }
  if (version) header.setVersion(version);
  if (method) header.setMethod(method);
  if (uri) header.setURI(new URI(uri, escaped));
  if (cookies) header.setCookies(cookies);
  if (secure === true || secure === false) header.setSecure(secure);
  if (user_agent) header.setDefaultUserAgent(user_agent);

  return request;
}

function buildNewMessage(
  version,
  secure,
  uri,
  escaped,
  method,
  data,
  charset,
  encode,
  content_type,
  cookies,
  user_agent
) {
  return buildFromMessage(
    new HttpMessage(),
    version,
    secure,
    uri,
    escaped,
    method,
    data,
    charset,
    encode,
    content_type,
    cookies,
    user_agent
  );
}

function buildPreAuthMessage() {
  return buildNewMessage(
    HTTP_VERSION,
    null,
    PRE_AUTH_GET,
    false,
    HttpRequestHeader.GET
  );
}

function buildAuthMessage(session, csrf) {
  var cookie = new HttpCookie(SESSION_COOKIE_NAME, session);
  var cookies = [cookie];
  var message = buildNewMessage(
    HTTP_VERSION,
    null,
    AUTH_POST,
    false,
    HttpRequestHeader.POST,
    LOGIN_DATA,
    DATA_CHARSET,
    false,
    HttpHeader.FORM_URLENCODED_CONTENT_TYPE,
    cookies
  );
  if (hasValue(csrf)) replaceCSRF(message, csrf);
  return message;
}

/**
 * @param msg: final (won't be modified)
 */
function buildRequestCSRF(msg, session) {
  var cookie = new HttpCookie(SESSION_COOKIE_NAME, session);
  var cookies = [cookie];
  var message = buildNewMessage(
    HTTP_VERSION,
    null,
    CSRF_GET,
    false,
    HttpRequestHeader.GET,
    "",
    DATA_CHARSET,
    false,
    null,
    cookies
  );
  return message;
}

function doAuth(helper) {
  var preAuthData = doAuthInternal(
    buildPreAuthMessage(),
    helper,
    true,
    AUTH_RETRIES,
    "POST-FOR-PRE-AUTH"
  );
  log(
    "{ method: doAuth (pre-login): response { " +
      "session: " +
      (preAuthData ? preAuthData.session : null) +
      ", " +
      "csrf: " +
      (preAuthData ? preAuthData.csrf : null) +
      "}}"
  );
  if (!preAuthData) return null;

  var authMessage = buildAuthMessage(preAuthData.session, preAuthData.csrf);
  var authData = doAuthInternal(
    authMessage,
    helper,
    true,
    AUTH_RETRIES,
    "POST-FOR-AUTH"
  );
  log(
    "{ method: doAuth (login): response { " +
      "session: " +
      (authData ? authData.session : null) +
      ", " +
      "csrf: " +
      (authData ? authData.csrf : null) +
      "}}"
  );
  if (!authData) return null;

  return new AuthInfo(authData.session, authData.csrf);
}

/**
 * @param msg modified
 */
function doAuthInternal(msg, helper, follow_redirects, retries, note) {
  for (var i = AUTH_INTERNALL_RETRIES; i > 0; --i) {
    var message = doRequest(msg, helper, follow_redirects, retries, note);
    if (message != null) {
      var session = getSessionCookie(message, HOST, SESSION_COOKIE_NAME);
      var csrf = extractCSRF(msg, CSRF_PARAM_NAME, CSRF_HEADER_NAME);
      return { session: session, csrf: csrf };
    } else {
      try {
        Thread.sleep(AUTH_INTERNALL_ERR_DELAY);
      } catch (e) {
        log("{ method: doAuthInternal { sleep-failed: " + e + " }");
      }
    }
  }
  log("{ method: doAuthInternal, " + note + " process failed! }");
  return null;
}

function invalidationLogic(responseHeader, session, r_code) {
  if (r_code == 401 || r_code == 403) {
    log("{ method: invalidationLogic (" + r_code + "), invalidating-session }");
    return true;
  } else if (r_code == 302) {
    var arr = responseHeader.getHeaderValues("Location");
    if (arr.length > 0 && arr[0] === UNAUTH_LOCATION) {
      log(
        "{ method: invalidationLogic (" + r_code + "), invalidating-session }"
      );
      return true;
    } else return false;
  }
}

function replaceAuthInfo(msg, authInfo) {
  if (hasValue(authInfo.csrf)) {
    replaceCSRF(msg, authInfo.csrf);
  } else log("{ method: replaceAuthInfo, no CSRF param to replace found }");

  if (hasValue(authInfo.session)) {
    var added = addOrReplaceSessionCookie(msg, authInfo.session);
    log(
      "{ method: replaceAuthInfo, sessionCookie: " +
        (added ? "replaced" : "pushed") +
        "  }"
    );
  } else log("{ method: replaceAuthInfo, sessionCookie not found! }");
}

function getSessionCookie(msg, domain, sessionCookieName) {
  var cookie = null;
  var cookies = msg.getResponseHeader().getHttpCookies(domain);
  log("{ method: getSessionCookie, cookies: " + cookies + " }");
  for (var i in cookies) {
    if (cookies[i].getName() == sessionCookieName)
      cookie = cookies[i].getValue();
  }
  return cookie;
}

function addOrReplaceSessionCookie(msg, session) {
  log("{ method: addOrReplaceSessionCookie, replacing sessionCookie }");

  var requestHeader = msg.getRequestHeader();
  var cookies = requestHeader.getHttpCookies();

  var current = null;
  var notFound = true;
  for (var i in cookies) {
    current = cookies[i];
    if (current.getName() == SESSION_COOKIE_NAME) {
      current.setValue(session);
      notFound = false;
    }
  }

  if (notFound) cookies.add(new HttpCookie(SESSION_COOKIE_NAME, session));

  requestHeader.setCookies(cookies);

  return notFound;
}

function getCSRF(msg, session, helper) {
  var current = extractCSRF(msg, CSRF_PARAM_NAME, CSRF_HEADER_NAME);
  if (hasValue(current)) {
    log("{ method: getCSRF, csrf: " + current + " }");
    return current;
  } else {
    current = requestCSRF(msg, session, helper);
    if (hasValue(current)) {
      log("{ method: getCSRF, csrf: " + current + " }");
      return current;
    }
  }
  log("{ method: getCSRF, csrf: update-failed! }");
  return null;
}

function requestCSRF(msg, session, helper) {
  var csrfMessage = doRequest(
    buildRequestCSRF(msg, session),
    helper,
    true,
    CSRF_RETRIES,
    "GET-FOR-CSRF"
  );
  if (csrfMessage == null) return null;
  return extractCSRF(csrfMessage, CSRF_PARAM_NAME, CSRF_HEADER_NAME);
}

function extractCSRF(msg, csrfFormName, csrfHeaderName) {
  var value = msg.getResponseHeader().getHeaderValues(csrfHeaderName);
  if (hasValue(value)) return value;

  value = extractValue(
    msg.getResponseBody().toString(),
    csrfFormName,
    "meta",
    "content"
  );
  if (hasValue(value)) return value;

  value = extractValue(
    msg.getResponseBody().toString(),
    csrfFormName,
    "input",
    "value"
  );
  if (hasValue(value)) return value;

  return null;
}

function replaceCSRF(msg, csrf) {
  var r_count_h = replaceHeaderCSRF(msg, csrf);
  var r_count_p = replacePostCSRF(msg, csrf);
  var r_count_g = replaceGetCSRF(msg, csrf);
  log(
    "{ method: replaceAuthInfo, " +
      "csrf@header: " +
      (r_count_h ? "set" : "missing") +
      ", csrf@post: replaced " +
      r_count_p +
      " times " +
      ", csrf@get: replaced " +
      r_count_g +
      " times }"
  );
}

function replaceHeaderCSRF(msg, csrf) {
  var requestHeader = msg.getRequestHeader();
  var n = requestHeader.getHeaderValues(CSRF_HEADER_NAME).size();
  if (n > 0) {
    requestHeader.setHeader(CSRF_HEADER_NAME, csrf);
    if (n > 1)
      log("{ method: replaceHeaderCSRF, warn-header-appears-" + n + "-times }");
  }
  return n;
}

function replacePostCSRF(msg, csrf) {
  var requestHeader = msg.getRequestHeader();
  var requestBody = msg.getRequestBody();
  var formParams = msg.getFormParams();
  var ret = replaceCSRFParams(formParams, csrf);
  if (ret.count > 0) {
    requestBody.setFormParams(ret.params);
    requestHeader.setContentLength(requestBody.length());
  }
  return ret.count;
}

function replaceGetCSRF(msg, csrf) {
  var urlParams = msg.getUrlParams();
  var ret = replaceCSRFParams(urlParams, csrf);
  if (ret.count > 0) {
    msg.setGetParams(ret.params);
    log(
      "{ method: replaceGetCSRF, warn-csrf-as-get-param-" +
        ret.count +
        "-times }"
    );
  }
  return ret.count;
}

function replaceCSRFParams(params, csrf) {
  if (!params || !csrf) return { count: 0, params: [] };
  var count = 0;
  params.forEach(function (e) {
    if (e.getName() == CSRF_PARAM_NAME) {
      e.setValue(csrf);
      ++count;
    }
  });
  return { count: count, params: params };
}

function extractValue(page, name, tag, att) {
  var src = new Source(page);
  var it = src.getAllElements(tag).iterator();
  while (it.hasNext()) {
    var element = it.next();
    if (element.getAttributeValue("name") == name) {
      return element.getAttributeValue(att);
    }
  }
  return null;
}

function procRC(responseHeader, r_code) {
  return r_code < 300 || r_code > 399
    ? r_code
    : r_code + ", location: " + responseHeader.getHeaderValues("Location");
}

function isCSRFRequired(msg) {
  var requestHeader = msg.getRequestHeader();
  return (
    requestHeader.getHeaderValues(CSRF_HEADER_NAME).size() > 0 ||
    isParamPresent(msg.getFormParams(), CSRF_PARAM_NAME) ||
    isParamPresent(msg.getUrlParams(), CSRF_PARAM_NAME)
  );
}

function isParamPresent(params, name) {
  for (var e in params) {
    if (e.getName().equals(name)) return true;
  }
  return false;
}

function hasValue(value) {
  if (value === null) return false;
  switch ({}.toString.call(value).split(" ")[1].slice(0, -1).toLowerCase()) {
    case "undefined":
      return false;
    case "boolean":
      return true;
    case "number":
      return true;
    case "string":
      return value.length > 0;
    case "object":
      return Object.keys(value).length > 0;
    default:
      return value.size();
  }
}

function valueOrZero(value) {
  return hasValue(value) ? value : 0;
}

function parseInitiator(initiator) {
  switch (initiator) {
    case HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR:
      return "ACCESS_CONTROL_SCANNER";
    case HttpSender.ACTIVE_SCANNER_INITIATOR:
      return "ACTIVE_SCANNER";
    case HttpSender.AJAX_SPIDER_INITIATOR:
      return "AJAX_SPIDER";
    case HttpSender.AUTHENTICATION_INITIATOR:
      return "AUTHENTICATOR";
    case HttpSender.BEAN_SHELL_INITIATOR:
      return "BEAN_SHELL";
    case HttpSender.FORCED_BROWSE_INITIATOR:
      return "FORCED_BROWSE";
    case HttpSender.FUZZER_INITIATOR:
      return "FUZZER";
    case HttpSender.MANUAL_REQUEST_INITIATOR:
      return "MANUAL_REQUEST";
    case HttpSender.PROXY_INITIATOR:
      return "PROXY";
    case HttpSender.SPIDER_INITIATOR:
      return "SPIDER";
    default:
      return initiator.name().replace(/_INITIATOR$/, "");
  }
}

function find(arr, f) {
  for (var i in arr) {
    var e = arr[i];
    if (f(e)) return e;
  }
  return null;
}

var writeToLog = function (text) {
  print(" -- { script: x-csrf-token, tid: " + ID() + ", info: " + text + " }");
};

var log = DO_LOG
  ? SYNC_LOG
    ? Java.synchronized(writeToLog, Byte.TYPE)
    : writeToLog
  : function () {};
