// This community script will analyze the response for base64 encoded strings
// Regex Test: https://regex101.com/r/pS2oF3/3

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100007
name: Information Disclosure - Base64-encoded String
description: >
  A Base64-encoded string has been found in the HTTP response body.
  Base64-encoded data may contain sensitive information such as usernames,
  passwords or cookies which should be further inspected.
solution: Base64-encoding should not be used to store or send sensitive information.
risk: info
confidence: low
cweId: 311  # CWE-311: Missing Encryption of Sensitive Data
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/find%20base64%20strings.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var RESULT_PER_FINDING = new Boolean(0); // If you want to see results on a per comment basis (i.e.: A single URL may be listed more than once), set this to true (1)
  var RESULT_PER_URL = new Boolean(1); // If you want to see results on a per URL basis (i.e.: all comments for a single URL will be grouped together), set this to true (1)
  var re = /([A-Za-z0-9+\/]{15,}=+)/g;

  var contenttype = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedfiletypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
  ];

  if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
    // skip scan if unwanted filetypes are found
    return;
  } else {
    var body = msg.getResponseBody().toString();
    if (re.test(body)) {
      re.lastIndex = 0;
      var foundstrings = [];
      var counter = 0;
      var comm;
      while ((comm = re.exec(body))) {
        if (RESULT_PER_FINDING == true) {
          counter = counter + 1;
          helper
            .newAlert()
            .setParam("fakeparam" + counter)
            .setEvidence(comm[0])
            .setMessage(msg)
            .raise();
        }
        foundstrings.push(comm[0]);
      }
      if (RESULT_PER_URL == true) {
        const otherInfo =
          foundstrings.length > 1
            ? `Other instances: ${foundstrings.slice(1).toString()}`
            : "";
        helper
          .newAlert()
          .setEvidence(foundstrings[0])
          .setOtherInfo(otherInfo)
          .setMessage(msg)
          .raise();
      }
    }
  }
}
