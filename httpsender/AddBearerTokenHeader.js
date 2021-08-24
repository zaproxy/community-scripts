/*
* This script is intended to be used along with Authentication/OfflineTokenRefresher.js to
* handle an OAUTH2 offline token refresh workflow.
*
* Authentication/OfflineTokenRefresher.js will automatically fetch the new access token for every unauthorized
* request determined by the "Logged Out" or "Logged In" indicator previously set in Context -> Authentication.
*
* HTTP Sender/AddBearerTokenHeader.js will add the new access token to all requests in scope
* made by ZAP (except the authentication ones) as an "Authorization: Bearer [access_token]" HTTP Header.
*
*
* @author Laura Pardo <lpardo at redhat.com>
*
*/

var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');

function sendingRequest(msg, initiator, helper) {

  // add Authorization header to all request in scope except the authorization request itself
  if (initiator !== HttpSender.AUTHENTICATION_INITIATOR && msg.isInScope()) {
    msg.getRequestHeader().setHeader("Authorization", "Bearer " + ScriptVars.getGlobalVar("access_token"));
  }

  return msg;
}

function responseReceived(msg, initiator, helper) {}
