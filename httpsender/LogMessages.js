// This script appends the full request and response details to a specified file.
// By default it will print out all messages but you can edit it to only print out the ones
// that you are interested in.
// It is a good option when trying to debug issues encountered when running ZAP in automation.
//
// The sendingRequest and responseReceived functions will be called for all requests/responses sent/received by ZAP,
// including automated tools (e.g. active scanner, fuzzer, ...)

// To use this script in the Docker packaged scans use the scan-hook LogRequestsHook.py
// This script can be used outside of docker but if so change the /zap/wrk/ directory to be a valid local directory.

// 'initiator' is the component the initiated the request.
// For the latest list of values see the "Request Initiator" entries in the constants documentation:
// https://www.zaproxy.org/docs/constants/
// 'helper' just has one method at the moment: helper.getHttpSender() which returns the HttpSender
// instance used to send the request.

var SEP = "\n ---------------------------------";
var Files = Java.type("java.nio.file.Files");
var Paths = Java.type("java.nio.file.Paths");
var StandardOpenOption = Java.type("java.nio.file.StandardOpenOption");

// Change this as required - this works well in Docker as long as a suitable local directory has been mapped to it
var f = Paths.get("/zap/wrk/req-resp-log.txt");

function appendToFile(str) {
  Files.write(
    f,
    str.toString().getBytes(),
    StandardOpenOption.CREATE,
    StandardOpenOption.APPEND
  );
}

function sendingRequest(msg, initiator, helper) {
  // You can change this to print out just the requests you want e.g. by surounding with an 'if' statement like:
  // if (msg.getRequestHeader().getURI().toString().startsWith('http://www.example.com'))
  // or
  // if (initiator == 5)

  // Print everything on one line so that threads dont mix the output
  appendToFile(
    SEP +
      "ZAP Request Init=" +
      initiator +
      "\n" +
      msg.getRequestHeader().toString() +
      SEP +
      "ZAP Request Body\n" +
      msg.getRequestBody().toString() +
      SEP +
      "ZAP Request End"
  );
}

function responseReceived(msg, initiator, helper) {
  // Print everything on one line so that threads dont mix the output
  appendToFile(
    SEP +
      "ZAP Response Init=" +
      initiator +
      "\n" +
      msg.getResponseHeader().toString() +
      SEP +
      "ZAP Response Body\n" +
      msg.getResponseBody().toString() +
      SEP +
      "ZAP Response End"
  );
}
