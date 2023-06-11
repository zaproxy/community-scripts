// This community script will analyze the response for base64 encoded strings
// Regex Test: https://regex101.com/r/pS2oF3/3


function scan(ps, msg, src) {
    var RESULT_PER_FINDING = new Boolean(0) // If you want to see results on a per comment basis (i.e.: A single URL may be listed more than once), set this to true (1)
    var RESULT_PER_URL = new Boolean(1) // If you want to see results on a per URL basis (i.e.: all comments for a single URL will be grouped together), set this to true (1)
	

    var alertRisk = 0
    var alertConfidence = 1
    var alertTitle = 'Base64-encoded string found (script)'
    var alertDesc = "A Base64-encoded string has been found in the HTTP response body. Base64-encoded data may contain sensitive information such as usernames, passwords or cookies which should be further inspected."
    var alertSolution = 'Base64-encoding should not be used to store or send sensitive information.'
    var cweId = 0
    var wascId = 0
    var url = msg.getRequestHeader().getURI().toString();
    var re = /(^[A-Za-z0-9+/]*={0,2}$)/g

    var contenttype = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// skip scan if unwanted filetypes are found
    		return
	}else{
        var body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0
            var foundstrings = []
            var counter=0
            var comm
            while (comm = re.exec(body)) {
                if (RESULT_PER_FINDING == true) {
                    counter = counter+1;
                    ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, 'fakeparam'+counter, '', comm[0], alertSolution,'' , cweId, wascId, msg);
                }
                foundstrings.push(comm[0]);
            }
            if (RESULT_PER_URL == true) 
            {
                ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', foundstrings.toString(), alertSolution,'' , cweId, wascId, msg);
            }
        }
    }
}
