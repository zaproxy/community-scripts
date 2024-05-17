/**
 * Copyright (C) 2021 Motorola Solutions, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Author: Piotr Furman <piotr.furman at motorolasolutions.com>
 *
 * Description:
 *
 * Script to validate potential Cross-Site WebSocket Hijacking vulnerability.
 *
 * According to RFC 6455, section 10.2 Origin Considerations:
 *
 * "Servers that are not intended to process input from any web page but
 * only for certain sites SHOULD verify the |Origin| field is an origin
 * they expect.  If the origin indicated is unacceptable to the server,
 * then it SHOULD respond to the WebSocket handshake with a reply
 * containing HTTP 403 Forbidden status code."
 *
 * Which means we can try to repeat WebSocket HTTP Upgrade request with
 * a modified Origin header and raise an alert if it was accepted.
 *
 * Note: Run ajax spider before a scan in order to evaluate your application's
 *       JavaScript code which opens WebSocket connection.
 * Note: Active scripts are initially disabled, right click the script to enable it.
 */

var Base64 = Java.type("java.util.Base64");
var Random = Java.type("java.util.Random");
var String = Java.type("java.lang.String");
var ByteArray = Java.type("byte[]");
var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");

var LOG_DEBUG_MESSAGES = false; // change to true for more logs

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100025
name: Cross-Site WebSocket Hijacking
description: Server accepted WebSocket connection through HTTP Upgrade request with modified Origin header.
solution: >
    Validate Origin header on WebSocket connection handshake, to ensure only specified origins are allowed to connect.
    Also, WebSocket handshake should use random tokens, similar to anti CSRF tokens.
references:
  - https://tools.ietf.org/html/rfc6455#section-10.2
category: server
risk: high
confidence: medium
cweId: 346  # CWE-346: Origin Validation Error
wascId: 9  # WASC-9 Cross Site Request Forgery
alertTags:
  ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue()}
  ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getTag()}: ${CommonAlertTag.WSTG_V42_CLNT_10_WEBSOCKETS.getValue()}
otherInfo: >
  See also https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
  or https://christian-schneider.net/CrossSiteWebSocketHijacking.html
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/Cross%20Site%20WebSocket%20Hijacking.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scanNode(as, msg) {
  var target = msg.getRequestHeader().getURI().toString();
  // check if this is a WebSocket HTTP Upgrade request
  if (msg.isWebSocketUpgrade()) {
    if (LOG_DEBUG_MESSAGES) {
      print(
        "Cross-Site WebSocket Hijacking rule skipped for url=" +
          target +
          ", it does not appear to be a WebSocket upgrade request"
      );
    }
    return;
  }

  if (LOG_DEBUG_MESSAGES) {
    print("Cross-Site WebSocket Hijacking rule started for url=" + target);
  }
  msg = msg.cloneRequest();

  // set random Sec-WebSocket-Key
  var randomBytes = new ByteArray(16);
  new Random().nextBytes(randomBytes);
  var secWsKey = new String(Base64.getEncoder().encode(randomBytes));
  msg.getRequestHeader().setHeader("Sec-WebSocket-Key", secWsKey);

  // set Origin header using custom domain, .example is a reserved TLD in RFC 2606 so it should not match domain name of a scanned service
  msg.getRequestHeader().setHeader("Origin", "https://cswsh.example");

  as.sendAndReceive(msg, true, false);

  var responseStatus = msg.getResponseHeader().getStatusCode();
  if (responseStatus === 101) {
    // should not have accepted connection with different origin
    if (LOG_DEBUG_MESSAGES) {
      print(
        "Cross-Site WebSocket Hijacking vulnerability found, sending alert for url=" +
          target
      );
    }
    as.newAlert()
      .setParam(target)
      .setEvidence(msg.getResponseHeader().getPrimeHeader())
      .setMessage(msg)
      .raise();
  }
}
