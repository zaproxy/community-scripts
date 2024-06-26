// Server Header Check by freakyclown@gmail.com
// Server Version leaks found via header field by prateek.rana@getastra.com

const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100019
name: Information Disclosure - Server Header
description: >
  The web/application server is leaking version information via the 'Server' HTTP response header.
  Access to such information may facilitate attackers identifying other vulnerabilities your web/application server 
  is subject to.
solution: >
  Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header 
  or provide generic details.
risk: low
confidence: medium
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Server%20Header%20Disclosure.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

var VERSION_PATTERN = new RegExp("(?:\\d+\\.)+\\d+");

function scan(helper, msg, src) {
  var headers = msg.getResponseHeader().getHeaders("Server");

  if (headers != null && containsPotentialSemver(headers)) {
    const otherInfo =
      headers.length > 1 ? `Other values: ${headers.slice(1).toString()}` : "";
    helper
      .newAlert()
      .setEvidence(headers[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
}

function containsPotentialSemver(content) {
  try {
    var res = VERSION_PATTERN.exec(content);
    if (res == null || res.join("") === "") {
      return false;
    }
    return true;
  } catch (err) {
    return false;
  }
}
