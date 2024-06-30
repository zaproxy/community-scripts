/*
 * Google API keys finder by SkypLabs.
 * https://blog.skyplabs.net
 * @SkypLabs
 */

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100034
name: Information Disclosure - Google API Key
description: A Google API Key was found in the HTTP response body.
solution: Ensure the API key is not overly permissive.
risk: info
confidence: high
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/google_api_keys_finder.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // Regex targeting Google API keys.
  // Taken from Table III of "How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories".
  // https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/
  var re = /AIza[0-9A-Za-z\-_]{35}/g;

  var url = msg.getRequestHeader().getURI().toString();

  // Do not scan unwanted file types.
  var contentType = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedFileTypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];

  if (unwantedFileTypes.indexOf("" + contentType) >= 0) {
    return;
  }

  var body = msg.getResponseBody().toString();

  if (re.test(body)) {
    re.lastIndex = 0;
    var foundKeys = [];
    var key;

    while ((key = re.exec(body))) {
      foundKeys.push(key[0]);
    }
    const otherInfo =
      foundKeys.length > 1
        ? `Other instances: ${foundKeys.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setEvidence(foundKeys[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
}
