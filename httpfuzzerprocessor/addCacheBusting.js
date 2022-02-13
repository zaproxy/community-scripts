function processMessage(utils, message) {
	var cbValue = Math.floor(Math.random() * 10000)
        setCacheBusting(message,cbValue);
	message.getRequestHeader().setHeader("X-Cache-Busting", cbValue);
}

function setCacheBusting(message,cbValue) {
    var URI = Java.type("org.apache.commons.httpclient.URI");
    var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter')
    var URL_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.url;
    var params = message.getUrlParams()
    var newParam = new HtmlParameter(URL_TYPE, "x_cache_busting_"+cbValue, cbValue);
    params.add(newParam)
    message.getRequestHeader().setGetParams(params)
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
