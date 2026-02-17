// CyberChef - Extract URLs (via /bake)
// https://www.zaproxy.org/blog/2026-02-17-encoder-cyberchef-via-scripts/

const EncodeDecodeResult = Java.type(
  "org.zaproxy.addon.encoder.processors.EncodeDecodeResult"
);
const HttpRequestHeader = Java.type(
  "org.parosproxy.paros.network.HttpRequestHeader"
);
const HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
const HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");

const cyberchefUrl = "http://localhost:3000/bake";

const header = new HttpRequestHeader("POST " + cyberchefUrl + " HTTP/1.1");
header.setHeader("Content-Type", "application/json");
header.setHeader("Accept", "application/json");

const msg = new HttpMessage(header);

const sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

function process(helper, value) {
  try {
    // This is the recipe/operation(s) we're going to ask CyberChef to handle
    // In this case if the input value is empty send a single space, otherwise CyberChef complains
    var payload = JSON.stringify({
      input: !value || value === "" ? " " : value,
      recipe: [{ op: "Extract URLs" }],
    });

    msg.setRequestBody(payload);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

    sender.sendAndReceive(msg);

    var responseStr = msg.getResponseBody().toString();

    // CyberChef /bake returns { "value": "...", "type": "string" }
    if (msg.getResponseHeader().isJson()) {
      var json = JSON.parse(responseStr);
      // If the return value is empty tell the user there's no URLs, otherwise provide them
      // Falling back to the raw response if it isn't JSON
      var output = json.value === "" ? "No URLs" : json.value || responseStr;
      return helper.newResult(output);
    }

    return helper.newResult(responseStr);
  } catch (e) {
    return helper.newError("Error contacting CyberChef: " + e.toString());
  }
}
