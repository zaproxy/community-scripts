// NOTE: This active scanner is VERY chatty, making a lot of request per URL
// Under certain conditions it can greatly increase your scan time and resource consumption

// Based on the Good-Old-File Extension by Hacktics: https://github.com/hacktics/good-old-files
//
// This script actively scans by altering the original requested URL in an attempt to find backup or archived
// versions of web content and components. Such as http://example.com/index.html also being
// available as: http://example.com/index.html.bak
//
// gof_lite.js
// Author: kingthorin
// 20150828 - Initial submission
// 20150923 - Add check to see and handle if the user has stopped the scan

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100030
name: Backup File Detected
description: >
  A backup or alternate version of a page or component was detected. An attacker
  may leverage information in such files to further attack or abuse the system.
solution: Ensure that backups are made in locations which are not web accessible.
category: info_gather
risk: low
confidence: medium
cweId: 425  # CWE-425: Direct Request ('Forced Browsing')
wascId: 34  # WASC-34: Predictable Resource Location
alertTags:
  ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES.getTag()}: ${CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES.getValue()}
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/gof_lite.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

mutationStrings = [
  "old",
  "conf",
  "1",
  "2",
  "12",
  "123",
  "txt",
  "bac",
  "bak",
  "backup",
  "asd",
  "dsa",
  "a",
  "aa",
  "aaa",
  "tar.gz",
  "tgz",
  "tar",
  "7z",
  "zip",
  "inc",
  "tmp",
  "temp",
];
//If your site/app returns not found content in a 200 Ok message (tsk tsk) you can define a matching string here to be interpreted as an error response
//The default setting "Sorry, we can't seem to find what you were looking for" is based upon some of the tests from WAVSEP: http://sourceforge.net/projects/wavsep/
customErrorString = "Sorry, we can't seem to find what you were looking for";

alertRiskDenied = 0;
alertConfidenceDenied = 1;
alertTitleDenied = "Backup File Detected (Access Denied)";
alertDescDenied =
  "A backup or alternate version of a page or component was detected, but the \
server denied access (HTTP 401 or 403). An attacker may leverage information in such files to further \
attack or abuse the system. In this case the file is of little use to an attacker, however this \
occurence may indicate that similar backups or alternatives are available elsewhere within the \
site or app.";

function scanNode(as, msg) {
  var origMsg = msg;
  var origURL = origMsg.getRequestHeader().getURI().toString();
  var origPath = origMsg.getRequestHeader().getURI().getPath();

  //Check if no path or root slash so skip i.e.: http://example.com/
  if (origPath == null || origPath.length() == 1) {
    return;
  }

  for (var idx in mutationStrings) {
    if (as.isStop()) {
      //Check if the user stopped the scan
      return;
    }
    msg = origMsg.cloneRequest(); // Copy requests before reusing them
    msg
      .getRequestHeader()
      .getURI()
      .setPath(mutate(msg, "." + mutationStrings[idx])); //TODO: handle separators other than period

    var newURL = msg.getRequestHeader().getURI().toString();
    if (newURL.equals(origURL)) {
      // Don't bother if no change (perhaps the user already proxied a backup/alternative)
      return;
    }

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    as.sendAndReceive(msg, false, false);

    var statusCode = msg.getResponseHeader().getStatusCode();
    switch (true) {
      case statusCode == 200:
        if (msg.getResponseBody().toString().contains(customErrorString)) {
          break; //200 - Ok w/ custom error message content
        }
        raiseAlert(true, msg, origMsg, as);
        break;
      case statusCode == 401: //Auth Failed
      case statusCode == 403: //Forbidden
        raiseAlert(false, msg, origMsg, as);
        break;
      case statusCode >= 500:
      //500 Internal Server Error (TODO: decide how to handle this case)
      default: //Other status/failure
        break;
    }
  }
}

function mutate(msg, mutationString) {
  var path = msg.getRequestHeader().getURI().getPath(); //getURI might include query, might need getPath/setPath

  if (path.toString().endsWith("/")) {
    //Non-root slash (root slash was skipped earlier)
    var trimmedPath = path.substring(0, path.length() - 1); //Everything but the final slash
    var newPath = trimmedPath + mutationString + "/";
    return newPath;
  } else {
    //File
    newPath = path + mutationString;
    return newPath;
  }
}

function raiseAlert(wasSuccess, msg, origMsg, as) {
  var alert = as.newAlert().setMessage(msg);
  if (!wasSuccess) {
    //401 or 403
    alert
      .setRisk(alertRiskDenied)
      .setConfidence(alertConfidenceDenied)
      .setName(alertTitleDenied)
      .setDescription(alertDescDenied);
  }
  alert.raise();
}
//TODO List
//Handle various prefixes and suffixes such as:
// 	* Copy of <filename>
//	* Copy - <filename>
//	* <filename> (#)
//	* <filename> - Copy
//Handle a list of punctuation, such as {'.','_','-',' '}, before extensions
//Handle replacement of file extensions, such that filename.ext becomes filename.bak, etc
//Handle scan strength settings
//Evaluate handling for other HTTP Status codes
//Implement more robust customErrorMessage checking (multiple strings?, custom URLs?, RegEx?)
//Evaluate handling for redirect responses (might be redirecting to a custom error page)
