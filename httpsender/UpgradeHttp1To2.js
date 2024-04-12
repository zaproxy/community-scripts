// Upgrade HTTP/1.1 requests to use HTTP/2
// This script can be used to force ZAP tools like the spider and importing add-ons to use HTTP/2
// If the target server does not support HTTP/2 then requests will fail - there is no fallback.

var Locale = Java.type("java.util.Locale");

function sendingRequest(msg, initiator, helper) {
  var reqHeader = msg.getRequestHeader();
  if (reqHeader.getVersion() === "HTTP/1.1") {
    // print('Upgrading to HTTP/2 url=' + msg.getRequestHeader().getURI().toString())
    reqHeader.setVersion("HTTP/2");
    // HTTP/2 headers have to be lowercase, so re-add them all to ensure the order is not changed
    var headers = reqHeader.getHeaders();
    for (i in headers) {
      reqHeader.setHeader(headers[i].getName(), null);
    }
    // Re-add in a second loop in case a header appears twice
    for (i in headers) {
      reqHeader.addHeader(
        headers[i].getName().toLowerCase(Locale.ROOT),
        headers[i].getValue()
      );
    }
  }
}

function responseReceived(msg, initiator, helper) {
  // Nothing to do
}
