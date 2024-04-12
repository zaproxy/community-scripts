/*
 * A script to provide authentication for Django apps.
 *
 * First it makes a GET request and obtains the csrfmiddlewaretoken from the response body.
 *
 * Then it makes a POST request with a body which contains username, password and csrfmiddlewaretoken.
 *
 * A successful login will result in a 302 redirect. If this happens, a GET request is made to the redirect URL.
 *
 * Every request made by this script is logged separately to the History tab.
 */

function authenticate(helper, paramsValues, credentials) {
  var AuthenticationHelper = Java.type(
    "org.zaproxy.zap.authentication.AuthenticationHelper"
  );
  var HttpRequestHeader = Java.type(
    "org.parosproxy.paros.network.HttpRequestHeader"
  );
  var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
  var URI = Java.type("org.apache.commons.httpclient.URI");

  var targetURL = paramsValues.get("Target URL");
  var baseURL = targetURL.match(/^(.+?[^\/:](?=[?\/]|$))/i)[1];

  //
  // First, make a GET request to the login page to get and extract the
  // csrfmiddlewaretoken from it.
  //

  // Build message.
  var firstRequestURI = new URI(targetURL, false);
  var firstRequestMethod = HttpRequestHeader.GET;
  var firstRequestMainHeader = new HttpRequestHeader(
    firstRequestMethod,
    firstRequestURI,
    HttpHeader.HTTP11
  );
  var firstMsg = helper.prepareMessage();
  firstMsg.setRequestHeader(firstRequestMainHeader);

  // Send message.
  helper.sendAndReceive(firstMsg, false);

  // Add message to ZAP history.
  AuthenticationHelper.addAuthMessageToHistory(firstMsg);

  // Get the csrf token from the response.
  var csrfTokenValueRegEx =
    /name="csrfmiddlewaretoken"\svalue="([A-Za-z0-9]*)"/i;
  var csrfTokenValue = firstMsg
    .getResponseBody()
    .toString()
    .match(csrfTokenValueRegEx)[1];

  //
  // Now, make a POST request to the login page with user credentials and
  // csrfmiddlewaretoken.
  //

  // Build body.
  var secondRequestBody = "csrfmiddlewaretoken=" + csrfTokenValue;
  secondRequestBody +=
    "&" +
    paramsValues.get("Username field") +
    "=" +
    encodeURIComponent(credentials.getParam("Username"));
  secondRequestBody +=
    "&" +
    paramsValues.get("Password field") +
    "=" +
    encodeURIComponent(credentials.getParam("Password"));
  var extraPostData = paramsValues.get("Extra POST data");
  if (extraPostData && extraPostData.trim().length() > 0) {
    secondRequestBody += "&" + extraPostData.trim();
  }

  // Build header.
  var secondRequestURI = new URI(targetURL, false);
  var secondRequestMethod = HttpRequestHeader.POST;
  var secondRequestMainHeader = new HttpRequestHeader(
    secondRequestMethod,
    secondRequestURI,
    HttpHeader.HTTP11
  );

  // Build message.
  var secondMsg = helper.prepareMessage();
  secondMsg.setRequestBody(secondRequestBody);
  secondMsg.setRequestHeader(secondRequestMainHeader);
  secondMsg
    .getRequestHeader()
    .setContentLength(secondMsg.getRequestBody().length());
  secondMsg.getRequestHeader().setHeader(HttpHeader.REFERER, targetURL); // Required by Django for HTTPS connections.

  // Send message.
  helper.sendAndReceive(secondMsg, false);

  // Get the status code of the response.
  var secondResponseStatusCode = secondMsg.getResponseHeader().getStatusCode();

  //
  // If the login is successful, the login page will respond with a 302
  // redirect. If it does, follow that redirect.
  //

  if (secondResponseStatusCode == "302") {
    // Add secondMsg to ZAP history
    AuthenticationHelper.addAuthMessageToHistory(secondMsg);

    // Build the URL to redirect to.
    var redirectURL =
      baseURL + secondMsg.getResponseHeader().getHeader("Location");

    // Build message.
    var thirdRequestURI = new URI(redirectURL, false);
    var thirdRequestMethod = HttpRequestHeader.GET;
    var thirdRequestMainHeader = new HttpRequestHeader(
      thirdRequestMethod,
      thirdRequestURI,
      HttpHeader.HTTP11
    );
    var thirdMsg = helper.prepareMessage();
    thirdMsg.setRequestHeader(thirdRequestMainHeader);

    // Send message.
    helper.sendAndReceive(thirdMsg, false);

    return thirdMsg;
  } else {
    return secondMsg;
  }
}

function getRequiredParamsNames() {
  return ["Target URL", "Username field", "Password field"];
}

function getOptionalParamsNames() {
  return ["Extra POST data"];
}

function getCredentialsParamsNames() {
  return ["Username", "Password"];
}
