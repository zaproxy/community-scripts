// The scan function will be called for request/response made via ZAP, excluding some of the automated tools
// Passive scan rules should not make any requests 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// kingthorin+owaspzap@gmail.com
// Ref: https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html

function scan(ps, msg, src) {
	//Setup some details we will need for alerts later if we find something
	alertRisk = 1
	alertConfidence = 3
	alertTitle = 'Internal IP Exposed via F5 BigIP Presistence Cookie'
	alertDesc = 'The F5 Big-IP Persistence cookie set for this website can be decoded to a specific internal IP and port. An attacker may leverage this information to conduct Social Engineering attacks or other exploits.'
	alertSolution = 'Configure BIG-IP cookie encryption.'
	alertRefs = 'https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html'
	cweId = 311
	wascId = 13

	url = msg.getRequestHeader().getURI().toString();
	//Only check when a cookie is set
	if(msg.getResponseHeader().getHeaders("Set-Cookie")) { 
		cookiesList = msg.getResponseHeader().getHttpCookies(); //Set-Cookie in Response
		cookiesList.addAll(msg.getRequestHeader().getHttpCookies()); //Cookie in Request
		cookiesArr  = cookiesList.toArray();
	
		for (idx in cookiesArr) {
			cookieName=cookiesArr[idx].getName();
			cookieValue=cookiesArr[idx].getValue();
			if(cookieName.toLowerCase().contains("bigip") &&
			  !cookiesArr[idx].getValue().toLowerCase().contains("deleted")) {
				cookieChunks = cookieValue.split("\\."); //i.e.: 3860990474.36895.0000
				//Decode IP
				theIP=decodeIP(cookieChunks[0]);
				//Decode Port
				thePort=decodePort(cookieChunks[1]);

				if(java.net.Inet4Address.getByName(theIP).isSiteLocalAddress()); { //RFC1918
					decodedValue=theIP+':'+thePort;
					alertOtherInfo=cookieValue+" decoded to "+decodedValue;
					//ps.raiseAlert(risk, confidence, title, description, url, param, attack, otherinfo, solution, evidence, cweId, wascId, msg);
					ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, 
						cookieName, '', alertOtherInfo, alertSolution+'\n'+alertRefs, 
						cookieValue, cweId, wascId, msg);
				}
			}
		}
	}
}

function decodeIP(ipChunk) {
	backwardIpHex = java.net.InetAddress.getByName(ipChunk);
	backwardAddress = backwardIpHex.getHostAddress();
	ipPieces = backwardAddress.split("\\.");
	theIP = ipPieces[3]+'.'+ipPieces[2]+'.'+ipPieces[1]+'.'+ipPieces[0]
	return theIP
}


function decodePort(portChunk) {
	backwardPortHex = java.lang.Integer.toHexString(java.lang.Integer.parseInt(portChunk));
	assembledPortHex = backwardPortHex.substring(2,4)+backwardPortHex.substring(0,2)
	thePort = java.lang.Integer.parseInt(assembledPortHex, 16);
	return(thePort);
}
