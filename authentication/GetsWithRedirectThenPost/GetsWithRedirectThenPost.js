// This script handles an authentication scheme with
// - n GET requests giving HTTP 302 redirect while potentially collecting cookies
// - then 1 POST request providing the login credentials to the server

// Don't forget to activate the "forced user mode" or the script will not trigger 

// More info: see README.md

// Make sure any Java classes used explicitly are imported
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type('org.parosproxy.paros.network.HttpHeader');
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');


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
    var host = paramsValues.get("Hostname without trailing slash")
    var firstGet = paramsValues.get("Fist get URI with leading slash, without trailing slash")

    // GET with redirects
    doGet(host + firstGet, helper);
    var statusCode = msg.getResponseHeader().getStatusCode();
    while (statusCode == 302) {
        // Add the request/response to ZAP history tab
        AuthenticationHelper.addAuthMessageToHistory(msg);
        // put host before in case of redirect with URI
        var redirectUrl = host + msg.getResponseHeader().getHeader('Location');
        doLog("Redirecting to: " + redirectUrl);
        doGet(redirectUrl, helper);
        statusCode = msg.getResponseHeader().getStatusCode();
    }

    // Post the authentication
    doPost(helper, paramsValues, credentials);
    return msg;
}


function doGet(url, helper) {
    var requestUri = new URI(url, false);
    var requestMethod = HttpRequestHeader.GET;

    // Build the GET request header
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP10);

    // Build the GET request message
    var msg = helper.prepareMessage();

    msg.setRequestHeader(requestHeader);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    // Send the GET request message
    doLog("Sending " + requestMethod + " request to " + requestUri);
    // false= do not follow redirect
    helper.sendAndReceive(msg, false);
    doLog("Received response status code: " + msg.getResponseHeader().getStatusCode());
}



function doPost(helper, paramsValues, credentials) {
    // Prepare the login submission request details
    var requestUri = new URI(paramsValues.get("Submission Form URL"), false);
    var requestMethod = HttpRequestHeader.POST;

    // Build the submission request body using the credential values
    var requestBody = paramsValues.get("Username field") + "=" + encodeURIComponent(credentials.getParam("usernameField"));
    requestBody += "&" + paramsValues.get("Password field") + "=" + encodeURIComponent(credentials.getParam("passwordField"));

    // Build the submission request header
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);

    // Build the submission request message
    var msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    // Send the submission request message
    doLog("Sending " + requestMethod + " request to " + requestUri + " with body: " + requestBody);
    // In case of redirect on the POST with the cookie not being set into the state, see TwoStepAuthentication.js
    helper.sendAndReceive(msg, true);
    doLog("Received response status code: " + msg.getResponseHeader().getStatusCode());
    // Add the request/response to ZAP history tab
    AuthenticationHelper.addAuthMessageToHistory(msg);
}



// This function is called during the script loading to obtain a list of the names of the required configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getRequiredParamsNames() {
    return ["Submission Form URL", "Username field", "Password field", "Fist get URI with leading slash, without trailing slash"];
}

// This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
// that will be shown in the Session Properties -  Authentication panel for configuration. They can be used
// to input dynamic data into the script, from the user interface (e.g. a login URL, name of POST parameters etc.)
function getOptionalParamsNames() {
    return ["Hostname without trailing slash"];
}

// This function is called during the script loading to obtain a list of the names of the parameters that are required,
// as credentials, for each User configured corresponding to an Authentication using this script
function getCredentialsParamsNames() {
    return ["usernameField", "passwordField"];
}


// For debugging purposes
function listRequestCookies(msg) {
    var cookies = msg.getRequestHeader().getHttpCookies() // This is a List<HttpCookie>
    var iterator = cookies.iterator()
    while (iterator.hasNext()) {
        var cookie = iterator.next() // This is a HttpCookie
        doLog(cookie.name + ":" + cookie.value);
    }
}

function getNow() {
    var objToday = new Date(),
        curYear = objToday.getFullYear(),
        curMonth = objToday.getMonth() < 10 ? "0" + objToday.getMonth() : objToday.getMonth(),
        dayOfMonth = (objToday.getDate() < 10) ? '0' + objToday.getDate() : objToday.getDate(),
        curHour = objToday.getHours() < 10 ? "0" + objToday.getHours() : objToday.getHours(),
        curMinute = objToday.getMinutes() < 10 ? "0" + objToday.getMinutes() : objToday.getMinutes(),
        curSeconds = objToday.getSeconds() < 10 ? "0" + objToday.getSeconds() : objToday.getSeconds(),
        today = curYear + curMonth + dayOfMonth + "_" + curHour + ":" + curMinute + ":" + curSeconds
    return today;
}

function doLog(text) {
    print(getNow() + " authent: " + text);
}
