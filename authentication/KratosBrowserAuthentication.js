/*
 * @description This script is used to authenticate a user using Ory Kratos self-service API for browser.
 *
 * Authentication Verification can be configured with the following rule:
 * - Verification Strategy: Poll the Specified URL
 * - Regex Pattern used to identify Logged In message: \Qactive.*
 * - URL to poll: <Kratos Base URL>/sessions/whoami
 *
 * Zap must be configured to use cookie-based session management.
 *
 * @author Edouard Maleix <ed@getlarge.eu>
 * @see https://www.ory.sh/docs/kratos/self-service/flows/user-login#login-for-server-side-browser-clients
 */

const HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader"
);
const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const URI = Java.type("org.apache.commons.httpclient.URI");
const AuthenticationHelper = Java.type(
  "org.zaproxy.zap.authentication.AuthenticationHelper"
);
const Source = Java.type("net.htmlparser.jericho.Source");

/**
 * @typedef {Object} AuthHelper
 * @property {function(): Object} prepareMessage - Prepares an HTTP message.
 * @property {function(Object, boolean=): void} sendAndReceive - Sends the HTTP message and receives the response.
 */

/**
 * @typedef {Object} ParamsValues
 * @property {function(string): string} get - Gets the value of a parameter.
 * @property {function(string): void} set - Sets the value of a parameter.
 */

/**
 * @typedef {Object} Credentials
 * @property {function(string): string} getParam - Gets the value of a parameter. The param	names are the ones returned by the getCredentialsParamsNames() below
 */

/**
 * @param {AuthHelper} helper - The authentication helper object provided by ZAP.
 * @param {ParamsValues} paramsValues - The map of parameter values configured in the Session Properties - Authentication panel.
 * @param {Credentials} credentials - an object containing the credentials values, as configured in the Session Properties - Users panel.
 * @returns {Object} The HTTP message used to perform the authentication.
 */
function authenticate(helper, paramsValues, credentials) {
  print("Authenticating via Ory Kratos...");

  // Step 1: Initialize the login flow
  const kratosBaseUri = paramsValues.get("Kratos Base URL");
  const initLoginUri = new URI(
    kratosBaseUri + "/self-service/login/browser",
    false
  );
  const initLoginMsg = helper.prepareMessage();
  initLoginMsg.setRequestHeader(
    new HttpRequestHeader(
      HttpRequestHeader.GET,
      initLoginUri,
      HttpHeader.HTTP11
    )
  );
  print("Sending GET request to " + initLoginUri);
  helper.sendAndReceive(initLoginMsg, true);
  print(
    "Received response status code: " +
      initLoginMsg.getResponseHeader().getStatusCode()
  );
  AuthenticationHelper.addAuthMessageToHistory(initLoginMsg);

  // Step 2: Submit login credentials
  const actionUrl = getActionurl(initLoginMsg);
  const loginUri = new URI(actionUrl, false);
  const loginMsg = helper.prepareMessage();
  const csrf_token = getCsrfToken(initLoginMsg);
  const requestBody =
    "identifier=" +
    encodeURIComponent(credentials.getParam("username")) +
    "&password=" +
    encodeURIComponent(credentials.getParam("password")) +
    "&method=password" +
    "&csrf_token=" +
    encodeURIComponent(csrf_token);
  loginMsg.setRequestBody(requestBody);
  const requestHeader = new HttpRequestHeader(
    HttpRequestHeader.POST,
    loginUri,
    HttpHeader.HTTP11
  );
  loginMsg.setRequestHeader(requestHeader);

  loginMsg
    .getRequestHeader()
    .setHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
  loginMsg
    .getRequestHeader()
    .setContentLength(loginMsg.getRequestBody().length());

  print("Sending POST request to " + loginUri);
  //! disable redirect to get the cookies from Kratos
  helper.sendAndReceive(loginMsg, false);
  print(
    "Received response status code: " +
      loginMsg.getResponseHeader().getStatusCode()
  );
  AuthenticationHelper.addAuthMessageToHistory(loginMsg);

  return loginMsg;
}

/**
 *
 * @param {*} request
 * @returns
 */
function getActionurl(request) {
  let iterator;
  let element;
  let actionUrl;
  const pageSource =
    request.getResponseHeader().toString() +
    request.getResponseBody().toString();
  const src = new Source(pageSource);
  const elements = src.getAllElements("form");

  for (iterator = elements.iterator(); iterator.hasNext(); ) {
    element = iterator.next();
    actionUrl = element.getAttributeValue("action");
    break;
  }

  return actionUrl;
}

function getCsrfToken(request) {
  let iterator;
  let element;
  let loginToken;
  const pageSource =
    request.getResponseHeader().toString() +
    request.getResponseBody().toString();
  const src = new Source(pageSource);
  const elements = src.getAllElements("input");

  for (iterator = elements.iterator(); iterator.hasNext(); ) {
    element = iterator.next();
    if (element.getAttributeValue("name") == "csrf_token") {
      loginToken = element.getAttributeValue("value");
      break;
    }
  }

  return loginToken;
}
/**
 * Returns the required parameter names.
 *
 * @returns {Array<string>} An array of required parameter names.
 */
function getRequiredParamsNames() {
  return ["Kratos Base URL"];
}

/**
 * Returns the optional parameter names.
 *
 * @returns {Array<string>} An array of optional parameter names.
 */
function getOptionalParamsNames() {
  return [];
}

/**
 * Returns the credentials parameter names.
 *
 * @returns {Array<string>} An array of credentials parameter names.
 */
function getCredentialsParamsNames() {
  return ["username", "password"];
}
