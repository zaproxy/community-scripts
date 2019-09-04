// The proxyRequest and proxyResponse functions will be called for all requests  and responses made via ZAP
// If they return 'false' then the corresponding request / response will be dropped.
// Right click the script in the Scripts tree and select "enable"

// Use the CSP header with any URL that contains one of these strings:
var watchedUrlStrings = ["hotels.", "example.com"];
var forceEnableEverywhere = false;

function proxyRequest(msg) {
	return true;
}

function proxyResponse(msg) {
	var url = msg.getRequestHeader().getURI().toString();
	print('proxyResponse called for url=' + url.substring(0, 80) +"...");
	// msg.setResponseBody(msg.getResponseBody().toString().replace("Example Domain","Test works"));
	// msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
	var relevant = forceEnableEverywhere;
	for(var i = 0; i<watchedUrlStrings.length; i++) {
		if(url.indexOf(watchedUrlStrings[i]) > -1) {
			relevant = true;
			break;
		}
	}
	if(relevant) {
		// set CSP header
		print("Setting CSP header...");
		var val = "default-src 'self' "; // TODO: INSERT YOUR POLICY HERE 
		var httpHeader = msg.getResponseHeader();
		httpHeader.setHeader("Content-Security-Policy-Report-Only", val);
		// test: httpHeader.setHeader("X-XSS-Protection", "1; mode=block")
		msg.setResponseHeader(httpHeader);
	}
	return true;
}
