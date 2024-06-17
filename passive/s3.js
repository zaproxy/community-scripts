// S3 bucket finder by alishasinghania09@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100036
name: Information Disclosure - Amazon S3 Bucket URL
description: An Amazon S3 bucket URL was found in the HTTP response body.
solution: Remove S3 Bucket names from the response or ensure that the permissions in bucket are configured properly.
risk: low
confidence: high
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/s3.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  // the regex for s3 bucket url and it must appear within /( and )/g
  var re = /((s3:\\[a-zA-Z0-9-\.\\_]+)|((s3-|s3\.)?(.*)\.amazonaws\.com))/g;

  // If the file type is image jpeg/png , then the scan will be skipped
  var contenttype = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedfiletypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];
  if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
    return;
  } else {
    // test the regex against the message body
    var body = msg.getResponseBody().toString();
    if (re.test(body)) {
      re.lastIndex = 0;
      var founds3bucket = [];
      var buckets;
      while ((buckets = re.exec(body))) {
        founds3bucket.push(buckets[0]);
      }
      //raise the alert
      helper
        .newAlert()
        .setEvidence(founds3bucket[0])
        .setOtherInfo(`Other instances: ${founds3bucket.slice(1).toString()}`)
        .setMessage(msg)
        .raise();
    }
  }
}
