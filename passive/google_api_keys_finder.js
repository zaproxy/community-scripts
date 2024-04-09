/*
 * Google API keys finder by SkypLabs.
 * https://blog.skyplabs.net
 * @SkypLabs
 */

function scan(ps, msg, src) {
  var alertRisk = 0; // Informational
  var alertConfidence = 3; // High
  var alertTitle = "Information Disclosure - Google API Keys Found";
  var alertDesc = "Google API keys have been found.";
  var alertSolution = "Make sure the API key is not overly permissive.";
  var cweId = 200; // "Exposure of Sensitive Information to an Unauthorized Actor"
  var wascId = 13; // "Information Leakage"

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

    ps.raiseAlert(
      alertRisk,
      alertConfidence,
      alertTitle,
      alertDesc,
      url,
      "",
      "",
      "The following Google API keys have been found in the page: " +
        foundKeys.join(", "), // Other info
      alertSolution,
      foundKeys[0].toString(), // Evidence
      cweId,
      wascId,
      msg
    );
  }
}
