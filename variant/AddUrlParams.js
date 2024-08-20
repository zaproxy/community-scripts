// The parseParameter function will typically be called for every page and
// the setParameter function is called by each active plugin to bundle specific attacks

// Note that new custom input vector scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

/*
This variant script adds arbitrary URL queries to all requests.
It can be used if you know (or suspect) that the target uses these parameters in some cases
and you want to make sure you test them on all pages, whether or not ZAP sees them being used.
*/

var AbstractPlugin = Java.type(
  "org.parosproxy.paros.core.scanner.AbstractPlugin"
);

function parseParameters(helper, msg) {
  // Add whichever parameters you need here, first is the name, the second is the default value
  // In this case they will be appended to all requests, but you can choose to only add
  // them to specific requests (like GETs) if you like by adding the relevant conditionals.
  helper.addParamQuery("q", "r");
  helper.addParamQuery("s", "t");
}

function setParameter(helper, msg, param, value, escaped) {
  var uri = msg.getRequestHeader().getURI();
  var query = uri.getEscapedQuery();
  if (query == null) {
    query = "";
  } else {
    query += "&";
  }
  query += param + "=";
  if (value == null) {
    value = "";
  }
  query += escaped ? value : AbstractPlugin.getURLEncode(value);
  uri.setEscapedQuery(query);
}
