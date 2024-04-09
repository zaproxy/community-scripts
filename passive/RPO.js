// RPO (Relative Path Overwrite) Finder by freakyclown@gmail.com
// influenced on burp-suites PRSSI scanner
// for more info see http://www.thespanner.co.uk/2014/03/21/rpo/
// *WARNING* this is a Beta version of this detection and may give many false positives!

function scan(ps, msg, src) {
  var url = msg.getRequestHeader().getURI().toString();
  var alertRisk = 2;
  var alertConfidence = 2;
  var alertTitle = "Potential Relative Path Overwrite - RPO(beta script)";
  var alertDesc = "Potential RPO (Relative Path Overwrite) found ";
  var alertSolution =
    "Make sure all style sheets are refered by full paths rather than relative paths.";

  var cweId = 0;
  var wascId = 0;
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
      ps.raiseAlert(
        alertRisk,
        alertConfidence,
        alertTitle,
        alertDesc,
        url,
        "",
        "",
        foundRPO.toString(),
        alertSolution,
        "",
        cweId,
        wascId,
        msg
      );
    }
  }
}
