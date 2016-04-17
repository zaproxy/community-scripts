/*
Script to detect if the site use the protection bring by the "SameSite" cookie attribute.

Knowing that point is interesting because the goal of this attribute is to mitigate CSRF attack.

Links:
- https://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue
- https://tools.ietf.org/html/draft-west-first-party-cookies
- https://www.chromestatus.com/feature/4672634709082112
*/

function scan(ps, msg, src) {
	//Docs on alert raising function:
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed

	//Common variables
	var cweId = 352; 
	var wascId = 9;
	var url = msg.getRequestHeader().getURI().toString();	
	var cookieHeaderNames = ["Set-Cookie", "Set-Cookie2"];
	var cookieSameSiteAttributeNameRef = "SameSite";

	//Response headers collection
	var responseHeaders = msg.getResponseHeader();

	//Detect and analyze presence of the cookie headers
	var cookieSameSiteAttributeNameLower = cookieSameSiteAttributeNameRef.toLowerCase().trim();
	for(var i = 0 ; i < cookieHeaderNames.length ; i++){
		var headerName = cookieHeaderNames[i];
		if(responseHeaders.getHeaders(headerName)){
			//Check if the cookie header values contains the SameSite attribute
			var headerValues = responseHeaders.getHeaders(headerName).toArray();
			for(var j = 0 ; j < headerValues.length ; j++){
				var cookieValue = headerValues[j].toLowerCase();
				var cookieAttributes = cookieValue.split(";");
				//Inspect each attribute in order to avoid false-positive spot
				//by simply searching "samesite=" on the whole cookie header value...
				var sameSiteAttrFound = false;
				var sameSiteAttrValue = null;
				for(var k = 0 ; k < cookieAttributes.length ; k++){
					var parts = cookieAttributes[k].split("=");
					if(parts[0].trim() === cookieSameSiteAttributeNameLower){
						sameSiteAttrFound = true;
						sameSiteAttrValue = parts[1].trim();
						break;
					}
				}
				//Analyze if the attribute is present and raise info alert
				if(sameSiteAttrFound){
					var cookieName = cookieAttributes[0].split("=")[0].trim();
					var description = "The current site use the 'SameSite' cookie attribute protection on cookie named '" + cookieName + "', value is set to '" + sameSiteAttrValue + "' protection level.";
					var infoLinkRef = "https://tools.ietf.org/html/draft-west-first-party-cookies\nhttps://chloe.re/2016/04/13/goodbye-csrf-samesite-to-the-rescue";	
					var solution = "CSRF possible vulnerabilities presents on the site will be mitigated depending on the browser used by the user (browser defines the support level for this cookie attribute).";				
					ps.raiseAlert(0, 4, "SameSite cookie attribute protection used", description, 
						url, "Cookie named: '" + cookieName + "'", "Non applicable", infoLinkRef, solution, "Protection level: " + sameSiteAttrValue, cweId, wascId, msg);							
				}
			}
		}
	}
}
