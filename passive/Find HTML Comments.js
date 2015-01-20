// html comment finder by freakyclown@gmail.com

function scan(ps, msg, src) {
	// lets set up some details we will need for alerts later if we find some comments
    alertRisk = 0
    alertReliability = 2
    alertTitle = 'Information Exposure Through HTML Comments (script)'
    alertDesc = 'While adding general comments is very useful, \
some programmers tend to leave important data, such as: filenames related to the web application, old links \
or links which were not meant to be browsed by users, old code fragments, etc.'
    alertSolution = 'Remove comments which have sensitive information about the design/implementation \
of the application. Some of the comments may be exposed to the user and affect the security posture of the \
application.'
    cweId = 615
    wascId = 13
    url = msg.getRequestHeader().getURI().toString();

	// this is a rough regular expression to find HTML comments
	// regex needs to be inside /( and )/g to work
    re = /(\<![\s]*--[-!@#$%^&*:;"'(){}\w\s\/\\[\]]*--[\s]*\>)/g

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    contenttype = msg.getResponseHeader().getHeader("Content-Type")
    unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
        body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0
            var foundComments = []
            while (comm = re.exec(body)) {
                foundComments.push(comm[0]);
            }
             ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundComments.toString(), alertSolution,'' , cweId, wascId, msg);
        }
    }
}
