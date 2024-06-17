// RPO (Relative Path Overwrite) Finder by freakyclown@gmail.com
// influenced on burp-suites PRSSI scanner
// for more info see http://www.thespanner.co.uk/2014/03/21/rpo/
// *WARNING* this is a Beta version of this detection and may give many false positives!

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100018
name: Relative Path Overwrite
description: >
  Potential RPO (Relative Path Overwrite) found.
  RPO allows attackers to manipulate URLs to include unintended paths,
  potentially leading to the execution of malicious scripts or the disclosure of sensitive information.
solution: >
  Use absolute paths in URLs and resources to prevent manipulation.
  Validate and sanitize all user inputs that are used to construct URLs.
risk: medium
confidence: medium
cweId: 20  # CWE-20: Improper Input Validation
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/RPO.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // regex must appear within /( and )/g
  var re = /(href\=\"((?!\/|http|www)).*\.css\")/g;

  // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
  var contenttype = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedfiletypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];

  if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
    // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    return;
  } else {
    var body = msg.getResponseBody().toString();

    if (re.test(body)) {
      re.lastIndex = 0; // After testing reset index
      // Look for RPO
      var foundRPO = [];
      var comm;
      while ((comm = re.exec(body))) {
        foundRPO.push(comm[0]);
      }
      helper
        .newAlert()
        .setEvidence(foundRPO[0])
        .setOtherInfo(`Other instances: ${foundRPO.slice(1).toString()}`)
        .setMessage(msg)
        .raise();
    }
  }
}
