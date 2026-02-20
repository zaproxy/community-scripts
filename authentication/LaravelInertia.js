/*
 * A script to provide authentication for Laravel InertiaJS apps.
 *
 * First it makes a GET request and obtains the XSRF-TOKEN and Cookie Session from the response body.
 *
 * Then it makes a POST request with a body which contains username, password and X-XSRF-TOKEN.
 *
 * A successful login will result in a 302 redirect. If this happens, a GET request is made to the redirect URL.
 *
 * Every request made by this script is logged separately to the History tab.
 */


function authenticate(helper, paramsValues, credentials) {

  var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');
  var HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");
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
  var firstRequestMainHeader = new HttpRequestHeader(firstRequestMethod, firstRequestURI, HttpHeader.HTTP11);
  var firstMsg = helper.prepareMessage();
  firstMsg.setRequestHeader(firstRequestMainHeader);


  // Send message.
  helper.sendAndReceive(firstMsg, false);

  // Add message to ZAP history.
  AuthenticationHelper.addAuthMessageToHistory(firstMsg);


  // Get the csrf token from the response.
  var csrfTokenValueRegEx = /XSRF-TOKEN=([A-Za-z0-9]*%3D)/i;

  var csrfTokenValue = firstMsg.getResponseHeader().toString().match(csrfTokenValueRegEx)[1];

  var cookieName = paramsValues.get("Session Cookie name") 
  // Get the csrf token from the response.
  var cookieSessionRegEx = /osdo_session=([A-Za-z0-9]*%3D)/i;
  var cookieSessionValue = firstMsg.getResponseHeader().toString().match(cookieSessionRegEx)[1];


  // Get Inertia version
  var dataPageRegEx = /<div id=\"app\" data-page=\"([^\"]+)\"/i
  var dataPageValue = firstMsg.getResponseBody().toString().match(dataPageRegEx)[1];

  var dataPageJsonString = dataPageValue.replace(/&quot;/g, '"');
  var dataPageObject = JSON.parse(dataPageJsonString);

  if (dataPageObject) {
    var inertiaVersion = dataPageObject.version;
  }

  // Now, make a POST request to the login page with user credentials and

  var secondRequestURI = new URI(targetURL, false);
  var secondRequestMethod = HttpRequestHeader.POST;
  var secondRequestHeader = new HttpRequestHeader(secondRequestMethod, secondRequestURI, HttpHeader.HTTP11);

  var secondMsg = helper.prepareMessage();
  secondMsg.setRequestHeader(secondRequestHeader);

  // add headers
  secondMsg.getRequestHeader().setHeader("X-XSRF-TOKEN", decodeURIComponent(csrfTokenValue));
  secondMsg.getRequestHeader().setHeader("Content-Type", "application/json");
  secondMsg.getRequestHeader().setHeader("X-Requested-With", "XMLHttpRequest");
  secondMsg.getRequestHeader().setHeader("Referer", targetURL);
  secondMsg.getRequestHeader().setHeader("X-Inertia", 'true');
  secondMsg.getRequestHeader().setHeader("X-Inertia-Version", inertiaVersion);
  secondMsg.getRequestHeader().setHeader("Accept", "text/html, application/xhtml+xml");

  // Send cookies
  secondMsg.getRequestHeader().setHeader(HttpHeader.COOKIE, "XSRF-TOKEN=" + csrfTokenValue + "; osdo_session=" + cookieSessionValue);

  // Build body credentials
  var postData = {
    paramsValues.get("Username field"): credentials.getParam("Username"),
    paramsValues.get("PPassword field") : credentials.getParam("Password"),
    "remember": ""
  };


  secondMsg.setRequestBody(JSON.stringify(postData));


  secondMsg.getRequestHeader().setContentLength(secondMsg.getRequestBody().length());

  helper.sendAndReceive(secondMsg, false);

  // Get the status code of the response.
  var secondResponseStatusCode = secondMsg.getResponseHeader().getStatusCode();

  //
  // If the login is successful, the login page will respond with a 302
  // redirect. If it does, follow that redirect.
  //
  if (secondResponseStatusCode == "302" && secondMsg.getResponseHeader().getHeader('Location') != targetURL) {
    // Add secondMsg to ZAP history
    AuthenticationHelper.addAuthMessageToHistory(secondMsg);

    // Build the URL to redirect to.
    var redirectURL = secondMsg.getResponseHeader().getHeader('Location');

    // Build message.
    var thirdRequestURI = new URI(redirectURL, false);
    var thirdRequestMethod = HttpRequestHeader.GET;
    var thirdRequestMainHeader = new HttpRequestHeader(thirdRequestMethod, thirdRequestURI, HttpHeader.HTTP11);
    var thirdMsg = helper.prepareMessage();
    thirdMsg.setRequestHeader(thirdRequestMainHeader);

    helper.sendAndReceive(thirdMsg, false);

    return thirdMsg;
  } else {
    return secondMsg;
  }

}


function getRequiredParamsNames() {
  return ["Target URL", "Username field", "Password field", "Session Cookie name"];
}

function getCredentialsParamsNames() {
  return ["Username", "Password"];
}
