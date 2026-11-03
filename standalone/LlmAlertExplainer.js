// Description: Sends ZAP alerts to an OpenAI-compatible chat completions endpoint and
//   prints an explanation plus remediation guidance for each alert. Useful for triaging
//   scan results or drafting report text. Run from the Script Console after a scan
//   (or after opening a session that has alerts).
// Author: Abliteration.ai (https://abliteration.ai)

// Configuration ----------------------------------------------------------------

// Base URL of any OpenAI-compatible API (no trailing slash).
// Default: Abliteration.ai (https://docs.abliteration.ai). Other examples:
//   OpenAI:        https://api.openai.com/v1
//   Ollama:        http://localhost:11434/v1
//   LM Studio:     http://localhost:1234/v1
var BASE_URL = "https://api.abliteration.ai/v1";

// Name of the environment variable holding the API key (never hardcode the key here).
// For OpenAI use "OPENAI_API_KEY"; local servers usually accept any non-empty value.
var API_KEY_ENV = "ABLIT_KEY";

// Model to request. For Abliteration.ai see https://docs.abliteration.ai/models
var MODEL = "abliterated-model";

// Only explain alerts whose URI starts with this value; empty string means all sites.
var SITE_FILTER = "";

// Maximum number of alerts to explain per run (each alert is one API call).
var MAX_ALERTS = 20;

// -------------------------------------------------------------------------------

var System = Java.type("java.lang.System");
var ExtensionAlert = Java.type(
  "org.zaproxy.zap.extension.alert.ExtensionAlert",
);
var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert");
var HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader",
);
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");

var sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

var SYSTEM_PROMPT =
  "You are a senior application security engineer. " +
  "For the given finding from an OWASP ZAP scan, explain in plain language: " +
  "what the issue is, how an attacker could exploit it, and how likely the " +
  "finding is to be a false positive. Then give concrete remediation guidance " +
  "with code or configuration examples where applicable. Be concise.";

function explain(alert) {
  var details =
    "Alert: " +
    alert.name +
    "\nRisk: " +
    Alert.MSG_RISK[alert.risk] +
    "\nConfidence: " +
    Alert.MSG_CONFIDENCE[alert.confidence] +
    "\nURL: " +
    alert.uri;
  if (alert.param) {
    details += "\nParameter: " + alert.param;
  }
  if (alert.attack) {
    details += "\nAttack: " + alert.attack;
  }
  if (alert.evidence) {
    details += "\nEvidence: " + alert.evidence;
  }
  details += "\nDescription: " + alert.description;
  if (alert.solution) {
    details += "\nSolution suggested by the scan rule: " + alert.solution;
  }

  var header = new HttpRequestHeader(
    "POST " + BASE_URL + "/chat/completions HTTP/1.1",
  );
  header.setHeader("Content-Type", "application/json");
  header.setHeader("Accept", "application/json");
  header.setHeader("Authorization", "Bearer " + apiKey);

  var msg = new HttpMessage(header);
  msg.setRequestBody(
    JSON.stringify({
      model: MODEL,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: details },
      ],
    }),
  );
  msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

  sender.sendAndReceive(msg);

  var status = msg.getResponseHeader().getStatusCode();
  var responseStr = msg.getResponseBody().toString();
  if (status !== 200) {
    return "Request failed with HTTP " + status + ": " + responseStr;
  }
  var json = JSON.parse(responseStr);
  if (!json.choices || !json.choices.length) {
    return "Unexpected response: " + responseStr;
  }
  return json.choices[0].message.content;
}

var apiKey = System.getenv(API_KEY_ENV);
if (!apiKey) {
  print(
    "API key not found. Set the " +
      API_KEY_ENV +
      " environment variable (or change API_KEY_ENV in the script) and re-run.",
  );
} else {
  var extAlert = control.getExtensionLoader().getExtension(ExtensionAlert.NAME);
  if (extAlert == null) {
    print("Could not access the alerts extension.");
  } else {
    var alerts = extAlert.getAllAlerts();
    var count = 0;
    for (var i = 0; i < alerts.length && count < MAX_ALERTS; i++) {
      var alert = alerts[i];
      if (SITE_FILTER && alert.uri.indexOf(SITE_FILTER) !== 0) {
        continue;
      }
      count++;
      print(
        "=== " +
          alert.name +
          " [" +
          Alert.MSG_RISK[alert.risk] +
          "] " +
          alert.uri +
          " ===",
      );
      try {
        print(explain(alert));
      } catch (e) {
        print("Error requesting explanation: " + e);
      }
      print("");
    }
    print(
      "Explained " +
        count +
        " of " +
        alerts.length +
        " alert(s). Tune SITE_FILTER and MAX_ALERTS at the top of the script.",
    );
  }
}
