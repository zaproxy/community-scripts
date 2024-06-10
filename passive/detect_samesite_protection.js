/*
Script to detect if the site use the protection bring by the "SameSite" cookie attribute.

Knowing that point is interesting because the goal of this attribute is to mitigate CSRF attack.

Links:
- https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue
- https://tools.ietf.org/html/draft-west-first-party-cookies
- https://www.chromestatus.com/feature/4672634709082112

Author:
dominique.righetto@gmail.com
*/

var Locale = Java.type("java.util.Locale");
var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100005
name: SameSite Cookie Attribute Protection Used
solution: >
  CSRF possible vulnerabilities presents on the site will be mitigated depending on the browser used by the user
  (browser defines the support level for this cookie attribute).
references:
  - https://tools.ietf.org/html/draft-west-first-party-cookies
  - https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue
risk: info
confidence: high
cweId: 352  # CWE-352: Cross-Site Request Forgery (CSRF)
wascId: 9  # WASC-9: Cross Site Request Forgery
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/detect_samesite_protection.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var cookieHeaderNames = ["Set-Cookie", "Set-Cookie2"];
  var cookieSameSiteAttributeNameLower = "samesite";

  //Response headers collection
  var responseHeaders = msg.getResponseHeader();

  //Detect and analyze presence of the cookie headers
  for (var i = 0; i < cookieHeaderNames.length; i++) {
    var headerName = cookieHeaderNames[i];
    if (responseHeaders.getHeaders(headerName)) {
      //Check if the cookie header values contains the SameSite attribute
      var headerValues = responseHeaders.getHeaders(headerName).toArray();
      for (var j = 0; j < headerValues.length; j++) {
        var cookieAttributes = headerValues[j].split(";");
        //Inspect each attribute in order to avoid false-positive spot
        //by simply searching "samesite=" on the whole cookie header value...
        for (var k = 0; k < cookieAttributes.length; k++) {
          var parts = cookieAttributes[k].split("=");
          if (
            parts[0].trim().toLowerCase(Locale.ROOT) ==
            cookieSameSiteAttributeNameLower
          ) {
            //Raise info alert
            var sameSiteAttrValue = parts[1].trim();
            var cookieName = cookieAttributes[0].split("=")[0].trim();
            var description =
              "The current site use the 'SameSite' cookie attribute protection on cookie named '" +
              cookieName +
              "', value is set to '" +
              sameSiteAttrValue +
              "' protection level.";
            helper
              .newAlert()
              .setDescription(description)
              .setParam("Cookie named: '" + cookieName + "'")
              .setEvidence(sameSiteAttrValue)
              .setMessage(msg)
              .raise();
            break;
          }
        }
      }
    }
  }
}
