// The scan function will be called for request/response made via ZAP, excluding some of the automated tools
// Passive scan rules should not make any requests

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

// PassiveHTMLCommentFinder.js
// Author: kingthorin

// References:
// RegEx Testing: http://regex101.com/r/tX1hS1
// Initial discussion: https://groups.google.com/forum/#!topic/zaproxy-develop/t-1-yI7iErw
// RegEx adapted from work by Stephen Ostermiller: http://ostermiller.org/findhtmlcomment.html
// Tweak to RegEx provided by thc202

// NOTE: Designed to work with 2.2 Weekly build version D-2014-03-10 or stable builds at or above v2.3
// NOTE: This script ONLY finds HTML comments. It DOES NOT find JavaScript or other comments.
// NOTE: This script will only find HTML comments in content which passes through ZAP.
//		Therefore if you browser is caching you may not see something you expect to.

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100011
name: Information Disclosure - HTML Comments
description: >
  While adding general comments is very useful, some programmers tend to leave important data,
  such as: filenames related to the web application, old links or links which were not meant
  to be browsed by users, old code fragments, etc.
solution: >
  Remove comments which have sensitive information about the design/implementation
  of the application. Some of the comments may be exposed to the user and affect 
  the security posture of the application.
risk: info
confidence: medium
cweId: 615  # CWE-615: Inclusion of Sensitive Information in Source Code Comments
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20HTML%20Comments.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // Both can be true, just know that you'll see duplication.
  var RESULT_PER_FINDING = new Boolean(0); // If you want to see results on a per comment basis (i.e.: A single URL may be listed more than once), set this to true (1)
  var RESULT_PER_URL = new Boolean(1); // If you want to see results on a per URL basis (i.e.: all comments for a single URL will be grouped together), set this to true (1)

  // this is a rough regular expression to find HTML comments
  // regex needs to be inside /( and )/g to work
  var re = /(\<![\s]*--[\-!@#$%^&*:;ºª.,"'(){}\w\s\/\\[\]]*--[\s]*\>)/g;

  // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
  var contenttype = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedfiletypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
  ];

  if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
    // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    return;
  } else {
    var body = msg.getResponseBody().toString();
    if (re.test(body)) {
      re.lastIndex = 0;
      var foundComments = [];
      var counter = 0;
      var comm;
      while ((comm = re.exec(body))) {
        if (RESULT_PER_FINDING == true) {
          counter = counter + 1;
          //fakeparam+counter gives us parameter differientiation per comment alert (RESULT_PER_FINDING)
          helper
            .newAlert()
            .setParam("fakeparam" + counter)
            .setEvidence(comm[0])
            .setMessage(msg)
            .raise();
        }
        foundComments.push(comm[0]);
      }
      if (RESULT_PER_URL == true) {
        helper
          .newAlert()
          .setEvidence(foundComments[0])
          .setOtherInfo(`Other instances: ${foundComments.slice(1).toString()}`)
          .setMessage(msg)
          .raise();
      }
    }
  }
}
