function processMessage(utils, message) {
	var cbValue = "cbvalue"+Math.floor(Math.random() * 10000)
     var updatedUrlParams = setCacheBusting(message,cbValue);
	message.getRequestHeader().setHeader("X-Cache-Busting", cbValue);
}

function setCacheBusting(message,cbValue) {
    var URI = Java.type("org.apache.commons.httpclient.URI");
    var params = message.getUrlParams();
    var iterator = params.iterator();

    if(iterator.hasNext()) {
      var uri = message.getRequestHeader().getURI().toString() + "&cbvalue="+cbValue
	 message.getRequestHeader().setURI(new URI(uri, false))
    } else {
      var uri = message.getRequestHeader().getURI().toString() + "?cbvalue="+cbValue
	 message.getRequestHeader().setURI(new URI(uri, false))
    }

    while(iterator.hasNext()) {
        var param = iterator.next();
        if (param.getName().equals("cachebusting")) {
		param.setValue(cbValue)
        }
    }
    return params;
}

function processResult(utils, fuzzResult){
	return true;
}

function getRequiredParamsNames(){
	return [];
}

function getOptionalParamsNames(){
	return [];
}
