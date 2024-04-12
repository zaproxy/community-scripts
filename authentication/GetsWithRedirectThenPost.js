// This script handles an authentication scheme with
// - n GET requests giving one of HTTP 301, 302, 303, 307, 308 (redirect) while potentially collecting cookies
// - then 1 POST request providing the login credentials to the server

// Detailed usage tutorial and a php back-end can be found at https://github.com/ptrovatelli/ZAP-authentication-script-tutorial-GetsWithRedirectsThenPost

// Make sure any Java classes used explicitly are imported
var HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader"
);
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type("org.apache.commons.httpclient.URI");
var AuthenticationHelper = Java.type(
  "org.zaproxy.zap.authentication.AuthenticationHelper"
);

// the maximum number of redirects we will follow (avoid infinite loops)
var MAX_REDIRECTS = 100;

// ------------------------------------
// Parameters
//   helper - a helper class providing useful methods: prepareMessage(), sendAndReceive(msg)
//   paramsValues - the values of the parameters configured in the Session Properties - Authentication panel.
//                      The paramsValues is a map, having as keys the parameters names (as returned by the
//                  getRequiredParamsNames() and getOptionalParamsNames() functions below)
//   credentials - an object containing the credentials values, as configured in the Session Properties - Users panel.
//                      The credential values can be obtained via calls to the getParam(paramName) method. The param
//                  names are the ones returned by the getCredentialsParamsNames() below
function authenticate(helper, paramsValues, credentials) {
  doLog("Authenticating via JavaScript script...");
  var host = paramsValues.get("Hostname without trailing slash");
  var firstGet = paramsValues.get(
    "First get URI with leading slash, without trailing slash"
  );

  // GET with redirects
  var msg = doGet(host + firstGet, helper);
  var statusCode = msg.getResponseHeader().getStatusCode();
  var nbRedirectsFollowed = 0;
  while (
    statusCode == 301 ||
    statusCode == 302 ||
    statusCode == 303 ||
    statusCode == 307 ||
    statusCode == 308
  ) {
    if (nbRedirectsFollowed >= MAX_REDIRECTS) {
      doLog("ERROR: Too many redirects. Stopped following redirects");
      break;
    }
    // Add the request/response to ZAP history tab
    AuthenticationHelper.addAuthMessageToHistory(msg);
    // put host before in case of redirect with URI
    var redirectUrl = host + msg.getResponseHeader().getHeader("Location");
    doLog("Redirecting to: " + redirectUrl);
    msg = doGet(redirectUrl, helper);
    statusCode = msg.getResponseHeader().getStatusCode();
    nbRedirectsFollowed++;
  }

  // Add last get to ZAP history
  AuthenticationHelper.addAuthMessageToHistory(msg);

  // Post the authentication
  msg = doPost(helper, paramsValues, credentials);
  return msg;
}

function doGet(url, helper) {
  //decode URI. Useful when there are encoded parameters in the URI
  var requestUri = new URI(decodeURIComponent(url), false);
  var requestMethod = HttpRequestHeader.GET;

  // Build the GET request header
  var requestHeader = new HttpRequestHeader(
    requestMethod,
    requestUri,
    HttpHeader.HTTP11
  );

  // Build the GET request message
  var msg = helper.prepareMessage();

  msg.setRequestHeader(requestHeader);
  msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

  // Send the GET request message
  doLog("Sending " + requestMethod + " request to " + requestUri);
  // sendAndReceive without following redirects
  // this allows us to manually add the redirect request/responses in ZAP history, making it much easier to understand what is going on.
  // With followRedirect=true, all request/responses and their cookies are aggregated in a single line in ZAP history tab.
  helper.sendAndReceive(msg, false);
  doLog(
    "Received response status code: " + msg.getResponseHeader().getStatusCode()
  );
  return msg;
}

function doPost(helper, paramsValues, credentials) {
  // Prepare the login submission request details
  var requestUri = new URI(paramsValues.get("Submission Form URL"), false);
  var requestMethod = HttpRequestHeader.POST;

  // Build the submission request body using the credential values
  var requestBody =
    paramsValues.get("Username field") +
    "=" +
    encodeURIComponent(credentials.getParam("usernameField"));
  requestBody +=
    "&" +
    paramsValues.get("Password field") +
    "=" +
    encodeURIComponent(credentials.getParam("passwordField"));

  // Build the submission request header
  var requestHeader = new HttpRequestHeader(
    requestMethod,
    requestUri,
    HttpHeader.HTTP11
  );

  // Build the submission request message
  var msg = helper.prepareMessage();
  msg.setRequestHeader(requestHeader);
  msg.setRequestBody(requestBody);
  msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

  // Send the submission request message
  doLog(
    "Sending " +
      requestMethod +
      " request to " +
      requestUri +
      " with body: " +
      requestBody
  );
  // In case of redirect on the POST with the cookie not being set into the state, see TwoStepAuthentication.js
  helper.sendAndReceive(msg, true);
  doLog(
    "Received response status code: " + msg.getResponseHeader().getStatusCode()
  );
  return msg;
}

// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames() {
  return [
    "Submission Form URL", // The url to POST to
    "Username field",
    "Password field",
    "First get URI with leading slash, without trailing slash", // Example: /test/get1.php
  ];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames() {
  return [
    "Hostname without trailing slash", // Example: https://myhostname.com. Useful when redirect target doesn't include the host but just an URI.
  ];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script
function getCredentialsParamsNames() {
  return ["usernameField", "passwordField"];
}

// For debugging purposes
function listRequestCookies(msg) {
  var cookies = msg.getRequestHeader().getHttpCookies(); // This is a List<HttpCookie>
  var iterator = cookies.iterator();
  while (iterator.hasNext()) {
    var cookie = iterator.next(); // This is a HttpCookie
    doLog(cookie.name + ":" + cookie.value);
  }
}

function getNow() {
  var objToday = new Date(),
    curYear = objToday.getFullYear(),
    curMonth =
      objToday.getMonth() < 10
        ? "0" + objToday.getMonth()
        : objToday.getMonth(),
    dayOfMonth =
      objToday.getDate() < 10 ? "0" + objToday.getDate() : objToday.getDate(),
    curHour =
      objToday.getHours() < 10
        ? "0" + objToday.getHours()
        : objToday.getHours(),
    curMinute =
      objToday.getMinutes() < 10
        ? "0" + objToday.getMinutes()
        : objToday.getMinutes(),
    curSeconds =
      objToday.getSeconds() < 10
        ? "0" + objToday.getSeconds()
        : objToday.getSeconds(),
    today =
      curYear +
      "." +
      curMonth +
      "." +
      dayOfMonth +
      "_" +
      curHour +
      ":" +
      curMinute +
      ":" +
      curSeconds;
  return today;
}

function doLog(text) {
  print(getNow() + " authent: " + text);
}
