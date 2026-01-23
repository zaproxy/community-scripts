const HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter");
const URL_TYPE = Java.type(
  "org.parosproxy.paros.network.HtmlParameter.Type.url"
);

function processMessage(utils, message) {
  var cbValue = "" + Math.floor(Math.random() * 10000);
  setCacheBusting(message, cbValue);
  message.getRequestHeader().setHeader("X-Cache-Busting", cbValue);
}

function setCacheBusting(message, cbValue) {
  var params = message.getUrlParams();
  var newParam = new HtmlParameter(
    URL_TYPE,
    "x_cache_busting_" + cbValue,
    cbValue
  );
  params.add(newParam);
  message.getRequestHeader().setGetParams(params);
}

function processResult(utils, fuzzResult) {
  return true;
}

function getRequiredParamsNames() {
  return [];
}

function getOptionalParamsNames() {
  return [];
}
