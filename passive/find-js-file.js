// Author: https://nmwafa.github.io - with GPT

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100021
name: JavaScript File Reference Detector
description: >
  Detects references to JavaScript (.js) files in HTML responses. 
  JavaScript files may expose sensitive information or be vulnerable 
  to client-side attacks if not reviewed.
solution: >
  Review all referenced JavaScript files. Ensure they do not contain 
  sensitive data (e.g., API keys, credentials) and follow secure coding practices.
risk: info
confidence: medium
cweId: 200   # CWE-200: Information Exposure
wascId: 13   # WASC-13: Information Leakage
status: alpha
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var contentType = msg.getResponseHeader().getHeader("Content-Type");
  if (!contentType || contentType.toLowerCase().indexOf("text/html") == -1) {
    return;
  }

  var body = msg.getResponseBody().toString();

  var regex = /["'(]([^"'()]+?\.js)(\?.*?)?["')]/gi;
  var matches = [];
  var found;

  while ((found = regex.exec(body)) !== null) {
    matches.push(found[1]);
  }

  if (matches.length > 0) {
    var mainEvidence = matches[0];
    var extraInfo =
      matches.length > 1
        ? "Additional JS files:\n" + matches.slice(1).join("\n")
        : "";

    helper
      .newAlert()
      .setName("JavaScript file detected")
      .setRisk(0)
      .setConfidence(1)
      .setEvidence(mainEvidence)
      .setOtherInfo(extraInfo)
      .setMessage(msg)
      .raise();
  }
}
