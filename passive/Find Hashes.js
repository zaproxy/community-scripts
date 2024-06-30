// Encryption Hash Finder by freakyclown@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100010
name: Information Disclosure - Hash
description: A hash was discovered in the HTTP response body.
solution: >
  Ensure that hashes that are used to protect credentials or other resources
  are not leaked by the web server or database. There is typically no requirement
  for password hashes to be accessible to the web browser.
risk: low
confidence: medium
cweId: 327  # CWE-327: Use of a Broken or Risky Cryptographic Algorithm
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20Hashes.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var body = msg.getResponseBody().toString();
  var alertTitle = [
    "Information Disclosure - Wordpress Hash",
    "Information Disclosure - Sha512 Hash",
    "Information Disclosure - phpBB3 Hash",
    "Information Disclosure - Joomla Hash",
    "Information Disclosure - MySQL(old) Hash",
    "Information Disclosure - Drupal Hash",
    "Information Disclosure - Blowfish Hash",
    "Information Disclosure - VBulletin Hash",
    "Information Disclosure - MD4/MD5 Hash",
    "",
  ];
  var alertDesc = [
    "A Wordpress hash was discovered.",
    "A Sha512 hash was discovered.",
    "A phpBB3 hash was discovered.",
    "A Joomla hash was discovered.",
    "A MySQL(old) hash was discovered.",
    "A Drupal hash was discovered.",
    "A Blowfish hash was discovered.",
    "A VBulletin hash was discovered.",
    "A MD4/MD5 hash Disclosed was discovered",
    "",
  ];

  // regex must appear within /( and )/g

  var wordpress = /(\$P\$\S{31})/g;
  var sha512 = /(\$6\$\w{8}\S{86})/g;
  var phpbb3 = /(\$H\$\S{31})/g;
  var joomla = /(([0-9a-zA-Z]{32}):(\w{16,32}))/g;
  var mysqlold = /([0-7][0-9a-f]{7}[0-7][0-9a-f]{7})/g;
  var drupal = /(\$\S\$\S{52})/g;
  var blowfish = /(\$2a\$8\$(.){75})/g;
  var vbull = /(([0-9a-zA-Z]{32}):(\S{3,32}))/g; //vbulletin
  var md45 = /([a-f0-9]{32})/g; //md4 and md5 and a bunch of others like tiger

  if (wordpress.test(body)) {
    wordpress.lastIndex = 0;
    var foundwordpress = [];
    var comm;
    while ((comm = wordpress.exec(body))) {
      foundwordpress.push(comm[0]);
    }
    const otherInfo =
      foundwordpress.length > 1
        ? `Other instances: ${foundwordpress.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[0])
      .setDescription(alertDesc[0])
      .setEvidence(foundwordpress[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (sha512.test(body)) {
    sha512.lastIndex = 0;
    var foundsha512 = [];
    while ((comm = sha512.exec(body))) {
      foundsha512.push(comm[0]);
    }
    const otherInfo =
      foundsha512.length > 1
        ? `Other instances: ${foundsha512.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[1])
      .setDescription(alertDesc[1])
      .setEvidence(foundsha512[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
  if (phpbb3.test(body)) {
    phpbb3.lastIndex = 0;
    var foundphpbb3 = [];
    while ((comm = phpbb3.exec(body))) {
      foundphpbb3.push(comm[0]);
    }
    const otherInfo =
      foundphpbb3.length > 1
        ? `Other instances: ${foundphpbb3.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[2])
      .setDescription(alertDesc[2])
      .setEvidence(foundphpbb3[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (mysqlold.test(body)) {
    mysqlold.lastIndex = 0;
    var foundmysqlold = [];
    while ((comm = mysqlold.exec(body))) {
      foundmysqlold.push(comm[0]);
    }
    const otherInfo =
      foundmysqlold.length > 1
        ? `Other instances: ${foundmysqlold.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[3])
      .setDescription(alertDesc[3])
      .setEvidence(foundmysqlold[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (joomla.test(body)) {
    joomla.lastIndex = 0;
    var foundjoomla = [];
    while ((comm = joomla.exec(body))) {
      foundjoomla.push(comm[0]);
    }
    const otherInfo =
      foundjoomla.length > 1
        ? `Other instances: ${foundjoomla.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[4])
      .setDescription(alertDesc[4])
      .setEvidence(foundjoomla[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
  if (drupal.test(body)) {
    drupal.lastIndex = 0;
    var founddrupal = [];
    while ((comm = drupal.exec(body))) {
      founddrupal.push(comm[0]);
    }
    const otherInfo =
      founddrupal.length > 1
        ? `Other instances: ${founddrupal.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[5])
      .setDescription(alertDesc[5])
      .setEvidence(founddrupal[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (blowfish.test(body)) {
    blowfish.lastIndex = 0;
    var foundblowfish = [];
    while ((comm = blowfish.exec(body))) {
      foundblowfish.push(comm[0]);
    }
    const otherInfo =
      foundblowfish.length > 1
        ? `Other instances: ${foundblowfish.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[6])
      .setDescription(alertDesc[6])
      .setEvidence(foundblowfish[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (vbull.test(body)) {
    vbull.lastIndex = 0;
    var foundvbull = [];
    while ((comm = vbull.exec(body))) {
      foundvbull.push(comm[0]);
    }
    const otherInfo =
      foundvbull.length > 1
        ? `Other instances: ${foundvbull.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[7])
      .setDescription(alertDesc[7])
      .setEvidence(foundvbull[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }

  if (md45.test(body)) {
    md45.lastIndex = 0;
    var foundmd45 = [];
    while ((comm = md45.exec(body))) {
      foundmd45.push(comm[0]);
    }
    const otherInfo =
      foundmd45.length > 1
        ? `Other instances: ${foundmd45.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setName(alertTitle[8])
      .setDescription(alertDesc[8])
      .setConfidence(1)
      .setEvidence(foundmd45[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
}
