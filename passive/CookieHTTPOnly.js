// Cookie HttpOnly Check by freakyclown@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100003
name: Cookie Set Without HttpOnly Flag
description: >
  A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript.
  If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site.
  If this is a session cookie then session hijacking may be possible.
solution: Ensure that the HttpOnly flag is set for all cookies.
risk: low
confidence: medium
cweId: 0
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/CookieHTTPOnly.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var cookies = msg.getResponseHeader().getHeaders("Set-Cookie");
  if (cookies != null) {
    var re_noflag = /([Hh][Tt][Tt][Pp][Oo][Nn][Ll][Yy])/g;
    if (!re_noflag.test(cookies.toString())) {
      const otherInfo =
        cookies.length > 1
          ? `Other values: ${cookies.slice(1).toString()}`
          : "";
      helper
        .newAlert()
        .setMessage(msg)
        .setEvidence(cookies[0])
        .setOtherInfo(otherInfo)
        .raise();
    }
  }
}
