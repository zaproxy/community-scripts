// This HttpSender script adds headers to all messages transmitted by zaproxy,
// including automated tools. Refer to the constants documentation:
// https://www.zaproxy.org/docs/constants/
// for a list of 'initiator' (Request Initiator) values (although we don't use them).

var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");

/*
 * HttpSender scripts do not support parameters, so we'll use a known global
 * variable to supply desired content. The value of this variable should be a
 * JSON string containing a serialized map<String, String> object. The map keys
 * are the desired header name and the values are the header values.
 *
 * Example:
 * add_headers defined with value '{"x-this": "v1", "x-that": "v2"}' will
 * result in the following headers being added to every request:
 * x-this: v1
 * x-that: v2
 */

PARAMETER_VARIABLE = "add_headers";
user_headers = null;

// Logging with the script name is super helpful!
function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
}

// Parse and store headers where we can get at them quickly
function initializeHeaders(variableName) {
  logger("Initializing...");
  user_headers = JSON.parse(ScriptVars.getGlobalVar(variableName));
}

/*
 * Processes messages by adding user-specified headers (overwriting original
 * values if header already exists). This may be pointless for some initiators
 * (CHECK_FOR_UPDATES) and redundant for others (FUZZER).
 *
 * Called before forwarding the message to the server.
 *
 * @param {HttpMessage} msg - The message that will be forwarded to the server.
 * @param {int} initiator - The initiator that generated the message.
 * @param {HttpSenderScriptHelper} helper - A utility object with helper functions.
 */
function sendingRequest(msg, initiator, helper) {
  // Get user-supplied headers if we didn't already do it
  if (!user_headers) {
    initializeHeaders(PARAMETER_VARIABLE);
  }

  // Ensure each header is present with the required value
  for (var key in user_headers) {
    var value = user_headers[key];
    // logger("Setting " + key + " to " + value);
    msg.getRequestHeader().setHeader(key, value);
  }
}

/* Called after receiving the response from the server.
 *
 * @param {HttpMessage} msg - The message that was forwarded to the server.
 * @param {int} initiator - The initiator that generated the message.
 * @param {HttpSenderScriptHelper} helper - A utility object with helper functions.
 */
function responseReceived(msg, initiator, helper) {
  // Nothing to do here
}
