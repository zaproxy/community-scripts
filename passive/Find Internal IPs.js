// RFC1918 internal IP Finder by freakyclown@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100013
name: Information Disclosure - Private IP Address
description: >
  A private IP such as 10.x.x.x, 172.x.x.x, 192.168.x.x or IPV6 fe00:: has been found in the HTTP response body.
  This information might be helpful for further attacks targeting internal systems.
solution: >
  Remove the private IP address from the HTTP response body.
  For comments, use JSP/ASP comment instead of HTML/JavaScript comment which can be seen by client browsers.
risk: medium
confidence: medium
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20Internal%20IPs.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // regex must appear within /( and )/g
  var re =
    /((172\.\d{1,3}\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|([fF][eE][89aAbBcCdDeEfF]::))/g;

  // you can tell the user in the console we are doing stuff by uncommenting the line below
  //print('Finding IPs Under: ' + url);

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
      re.lastIndex = 0; // After testing reset index
      // Look for IP addresses
      var foundIP = [];
      var comm;
      while ((comm = re.exec(body))) {
        foundIP.push(comm[0]);
      }
      const otherInfo =
        foundIP.length > 1
          ? `Other instances: ${foundIP.slice(1).toString()}`
          : "";
      helper
        .newAlert()
        .setEvidence(foundIP[0])
        .setOtherInfo(otherInfo)
        .setMessage(msg)
        .raise();
    }
  }
}
