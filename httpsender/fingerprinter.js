/*exported sendingRequest, responseReceived*/
// Logs md5 hashes of responses

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}

var String = Java.type("java.lang.String");
var BigInteger = Java.type("java.math.BigInteger");
var MessageDigest = Java.type("java.security.MessageDigest");

function sendingRequest(msg, initiator, helper) {}

function responseReceived(msg, initiator, helper) {
  var resbody = msg.getResponseBody().toString();
  var md5 = MessageDigest.getInstance("MD5");
  md5.reset();
  md5.update(resbody.getBytes());
  var fingerprint = String.format("%032x", new BigInteger(1, md5.digest()));
  logger(fingerprint);
}
