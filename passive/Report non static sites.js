// Raises a High alert if URL parameters or forms are detected.
// This script is only intended to be used on sites that are believed to be static.

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100017
name: Non Static Site Detected
description: >
  A query string or form has been detected in the HTTP response body.
  This indicates that this may not be a static site.
solution: >
  If this is not a static site then ignore or disable this rule.
risk: info
confidence: medium
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Report%20non%20static%20sites.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

/**
 * Passively scans an HTTP message. The scan function will be called for
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 *
 * @param helper - the PassiveScan parent object that will do all the core interface tasks
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.).
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */
function scan(helper, msg, src) {
  if (msg.getRequestHeader().getURI().getEscapedQuery() != null) {
    helper
      .newAlert()
      .setName("Non Static Site Detected (query present)")
      .setDescription(
        "A query string has been detected in the HTTP response body. This indicates that this may not be a static site."
      )
      .setEvidence(msg.getRequestHeader().getURI().getEscapedQuery())
      .setMessage(msg)
      .raise();
  }
  if (src != null && !src.getFormFields().isEmpty()) {
    // There are form fields
    helper
      .newAlert()
      .setName("Non Static Site Detected (form present)")
      .setDescription(
        "One or more forms have been detected in the response. This indicates that this may not be a static site."
      )
      .setEvidence(src.getFormFields().toString())
      .setMessage(msg)
      .raise();
  }
}

/**
 * Tells whether or not the scanner applies to the given history type.
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether or not the message with the given type should be scanned by this scanner.
 */
function appliesToHistoryType(historyType) {
  // For example, to just scan spider messages:
  // return historyType == org.parosproxy.paros.model.HistoryReference.TYPE_SPIDER;

  // Default behaviour scans default types.
  return org.zaproxy.zap.extension.pscan.PluginPassiveScanner.getDefaultHistoryTypes().contains(
    historyType
  );
}
