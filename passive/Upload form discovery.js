// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100022
name: Upload Form Discovered
description: >
  The presence of a file upload form can lead to various security vulnerabilities, such as uploading malicious files or
  overwriting existing files, if proper validation and restrictions are not implemented.
  This can result in unauthorized code execution, data breaches, or denial of service attacks.
solution: >
    Implement strict validation and restrictions on uploaded files, including file type, size, and content.
    Use security measures like antivirus scanning and file storage outside the web root.
risk: info
confidence: medium
cweId: 434  # CWE-434: Unrestricted Upload of File with Dangerous Type
wascId: 20  # WASC-20: Improper Input Handling
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Upload%20form%20discovery.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  const body = msg.getResponseBody().toString();
  const uploadForm = /(type\s*=\s*['"]?file['"]?)/g;

  if (uploadForm.test(body)) {
    uploadForm.lastIndex = 0;
    const foundUploadForm = [];
    let comm;
    while ((comm = uploadForm.exec(body))) {
      foundUploadForm.push(comm[0]);
    }
    const otherInfo =
      foundUploadForm.length > 1
        ? `Other instances: ${foundUploadForm.slice(1).toString()}`
        : "";
    helper
      .newAlert()
      .setEvidence(foundUploadForm[0])
      .setOtherInfo(otherInfo)
      .setMessage(msg)
      .raise();
  }
}
