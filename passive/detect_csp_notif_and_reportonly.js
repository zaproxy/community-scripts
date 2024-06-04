/*
Script to detect if the Content-Security-Policy policies defined for the current site:
- Send notifications about violations (some kind of monitoring),
- Behave into "report-only" mode (no blocking, only report violations).

These informations are interesting from an attacker/researcher point of view because it indicates to him:
1) His input validation probing tentatives will be potentially quickly detected (depending on the monitoring level by site owner),
2) The CSP policies in place will not block the exploitation if a vulnerability is found into input validation,
3) Perhaps the endpoint receiving notifications is vulnerable to some injection.

Links:
- http://content-security-policy.com
- http://www.html5rocks.com/en/tutorials/security/content-security-policy
- http://www.html5rocks.com/en/tutorials/security/content-security-policy/#reporting

Author:
dominique.righetto@gmail.com
*/

var Locale = Java.type("java.util.Locale");
var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100004
name: Content Security Policy Violations Reporting Enabled
solution: >
  Site owner will be notified at each policies violations, so, start by analyzing if a real monitoring of the
  notifications is in place before to use fuzzing or to be more aggressive.
references:
  - https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_CSP_violation_reports
risk: info
confidence: high
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/detect_csp_notif_and_reportonly.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function extractUrl(cspPolicies, cspReportInstruction) {
  //Extract the URL to which any CSP violations are reported
  //In CSP specification, policies are separated by ';'
  if (cspPolicies.indexOf(cspReportInstruction) != -1) {
    var startPosition = cspPolicies.search(cspReportInstruction);
    var tmp = cspPolicies.substring(startPosition);
    var endPosition = tmp.indexOf(";");
    if (endPosition != -1) {
      var reportUrl = tmp.substring(0, endPosition);
    } else {
      var reportUrl = tmp;
    }
    return reportUrl.replace(cspReportInstruction, "").trim();
  } else {
    return null;
  }
}

function scan(helper, msg, src) {
  var cspHeaderNames = [
    "Content-Security-Policy",
    "X-Content-Security-Policy",
    "X-Webkit-CSP",
    "Content-Security-Policy-Report-Only",
  ];
  var cspReportInstruction = "report-uri";

  var responseHeaders = msg.getResponseHeader();

  //Detect and analyze presence of the CSP headers
  for (var i = 0; i < cspHeaderNames.length; i++) {
    var headerName = cspHeaderNames[i];
    if (responseHeaders.getHeaders(headerName)) {
      //Check if the header values (policies) contains the CSP reporting instruction
      var headerValues = responseHeaders.getHeaders(headerName).toArray();
      for (var j = 0; j < headerValues.length; j++) {
        var cspPolicies = headerValues[j].toLowerCase(Locale.ROOT);
        //Extract the URL to which any CSP violations are reported if specified
        var reportUrl = extractUrl(cspPolicies, cspReportInstruction);
        if (reportUrl != null) {
          //Raise info alert
          var cspWorkingMode =
            headerName.toLowerCase(Locale.ROOT).indexOf("-report-only") == -1
              ? "BLOCKING"
              : "REPORTING";
          var description =
            "The current site CSP policies defined by HTTP response header '" +
            headerName +
            "' (behaving in " +
            cspWorkingMode +
            " mode) report violation to '" +
            reportUrl +
            "'.";
          helper
            .newAlert()
            .setDescription(description)
            .setParam("HTTP response header '" + headerName + "'")
            .setEvidence(headerValues[j])
            .setMessage(msg)
            .raise();
        }
      }
    }
  }
}
