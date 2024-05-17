// Clacks Header Check by freakyclown@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100002
name: Server is running on Clacks - GNU Terry Pratchett
description: > 
  The web/application server is running over the Clacks network, some say it's turtles/IP, 
  some say it's turtles all the way down the layer stack.
solution: Give the sysadmin a high five and rejoice in the disc world.
references:
  - https://xclacksoverhead.org/home/about
risk: info
confidence: high
cweId: 200  # CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
wascId: 13  # WASC-13: Information Leakage
status: alpha
`);
}

function scan(helper, msg, src) {
  var headers = msg.getResponseHeader().getHeaders("X-Clacks-Overhead");
  if (headers != null) {
    helper.newAlert().setMessage(msg).setEvidence(headers).raise();
  }
}
