// Email finder by freakyclown@gmail.com
// Based on:
// PassiveHTMLCommentFinder.js
// 20150106 - Updated by kingthorin to handle addresses (such as gmail) with alias portion:
//     https://support.google.com/mail/answer/12096?hl=en
//     https://regex101.com/r/sH4vC0/2
// 20181213 - Update by nil0x42+owaspzap@gmail.com to ignore false positives (such as '*@123' or '$@#!.')
// 20240604 - Implement getMetadata() to expose the script as a scan rule.

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100009
name: Information Disclosure - Email Addresses
description: >
  An email address was found in the HTTP response body.
  Exposure of email addresses in HTTP messages can lead to privacy violations 
  and targeted phishing attacks.
solution: >
  Mask email addresses during transmission and ensure proper access controls 
  to protect user privacy and prevent unauthorized access.
risk: low
confidence: high
cweId: 311  # CWE-311: Missing Encryption of Sensitive Data
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20Emails.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // lets build a regular expression that can find email addresses
  // the regex must appear within /( and )/g
  var re =
    /([a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+[a-zA-Z0-9-]*\.[a-zA-Z0-9-.]*[a-zA-Z0-9]{2,})/g;

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
    // now lets run our regex against the body response
    var body = msg.getResponseBody().toString();
    if (re.test(body)) {
      re.lastIndex = 0; // After testing reset index
      // Look for email addresses
      var foundEmail = [];
      var comm;
      while ((comm = re.exec(body))) {
        foundEmail.push(comm[0]);
      }
      // woohoo we found an email lets make an alert for it
      helper
        .newAlert()
        .setEvidence(foundEmail[0])
        .setOtherInfo(`Other instances: ${foundEmail.slice(1).toString()}`)
        .setMessage(msg)
        .raise();
    }
  }
}
