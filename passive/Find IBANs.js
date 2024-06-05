// IBAN finder by https://renouncedthoughts.wordpress.com
// Heavily inspired by Find Emails.js
// Regex evaluated at https://regexr.com/4kb6e
// Tested against sample vulnerable page https://neverwind.azurewebsites.net/Admin/Download/Get
// Runs as a part of nightly baseline scans in many DevSecOps environments
// Complements the Pluralsight course - Writing Custom Scripts for Zed Attack Proxy

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100012
name: Information Disclosure - IBAN Numbers
description: An IBAN number was discovered in the HTTP response body.
solution: Investigate IBAN numbers found in the response, remove or mask as required.
risk: low
confidence: high
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20IBANs.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // lets build a regular expression that can find IBAN addresses
  // the regex must appear within /( and )/g
  var re = /([A-Za-z]{2}[0-9]{2}[A-Za-z]{4}[0-9]{10})/g;

  // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
  var contentType = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedFileTypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];

  if (unwantedFileTypes.indexOf("" + contentType) >= 0) {
    // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    return;
  }
  // now lets run our regex against the body response
  var body = msg.getResponseBody().toString();
  if (re.test(body)) {
    re.lastIndex = 0; // After testing reset index
    // Look for IBAN addresses
    var foundIBAN = [];
    var comm;
    while ((comm = re.exec(body))) {
      foundIBAN.push(comm[0]);
    }
    // woohoo we found an IBAN lets make an alert for it
    helper
      .newAlert()
      .setEvidence(foundIBAN[0])
      .setOtherInfo(`Other instances: ${foundIBAN.slice(1).toString()}`)
      .setMessage(msg)
      .raise();
  }
}
