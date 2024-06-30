// X-Powered-By finder by freakyclown@gmail.com

const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100023
name: Information Disclosure - X-Powered-By Header
description: >
  The web/application server is leaking information via one or more 'X-Powered-By' HTTP response headers.
  Access to such information may facilitate attackers identifying other frameworks/components your web application
  is reliant upon and the vulnerabilities such components may be subject to.
solution: >
  Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers.
risk: low
confidence: medium
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/X-Powered-By_header_checker.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  const headers = msg.getResponseHeader().getHeaders("X-Powered-By");
  if (headers != null) {
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
