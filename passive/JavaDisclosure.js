//Passive scan for Java error messages containing sensitive information (CWE-209)

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100035
name: Information Disclosure - Java Stack Trace
description: A Java stack trace was found in the HTTP response body.
solution: >
  Catch and handle exceptions properly, avoiding the exposure of stack traces to users.
  Configure the web server or application framework to log stack traces instead of displaying them.
risk: medium
confidence: high
cweId: 209  # CWE-209: Generation of Error Message Containing Sensitive Information
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/JavaDisclosure.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var re = /springframework|\.java|rootBeanClass/i;

  var contentType = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedFileTypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];

  if (unwantedFileTypes.indexOf("" + contentType) >= 0) {
    return;
  }

  var body = msg.getResponseBody().toString();
  if (re.test(body)) {
    re.lastIndex = 0;
    var match = re.exec(body)[0];
    helper
      .newAlert()
      .setEvidence(match)
      .setOtherInfo(body)
      .setMessage(msg)
      .raise();
  }
}
