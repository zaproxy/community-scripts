function processMessage(utils, message) {
	var cbValue = Math.floor(Math.random() * 10000)
        setCacheBusting(message,cbValue);
	message.getRequestHeader().setHeader("X-Cache-Busting", cbValue);
}

function setCacheBusting(message,cbValue) {
    var URI = Java.type("org.apache.commons.httpclient.URI");
    var params = message.getUrlParams();
    var iterator = params.iterator();

    if(iterator.hasNext()) {
      var uri = message.getRequestHeader().getURI().toString() + "&x_cache_busting_"+cbValue+"="+cbValue
	 message.getRequestHeader().setURI(new URI(uri, false))
    } else {
      var uri = message.getRequestHeader().getURI().toString() + "?x_cache_busting_"+cbValue+"="+cbValue
	 message.getRequestHeader().setURI(new URI(uri, false))
    }
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
