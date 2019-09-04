// Email finder by freakyclown@gmail.com
// Based on:
// PassiveHTMLCommentFinder.js
// kingthorin+owaspzap@gmail.com
// 20150106 - Updated by kingthorin+owaspzap@gmail.com to handle addresses (such as gmail) with alias portion:
//     https://support.google.com/mail/answer/12096?hl=en
//     https://regex101.com/r/sH4vC0/2
// 20181213 - Update by nil0x42+owaspzap@gmail.com to ignore false positives (such as '*@123' or '$@#!.')

function scan(ps, msg, src) {
    // first lets set up some details incase we find an email, these will populate the alert later
    var alertRisk = 0
    var alertReliability = 3
    var alertTitle = 'Email addresses (script)'
    var alertDesc = 'Email addresses were found'
    var alertSolution = 'Remove emails that are not public'
    var cweId = 0
    var wascId = 0

	// lets build a regular expression that can find email addresses
	// the regex must appear within /( and )/g
    var re = /([a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+[a-zA-Z0-9-]*\.[a-zA-Z0-9-.]*[a-zA-Z0-9]{2,})/g

	// we need to set the url variable to the request or we cant track the alert later
    var url = msg.getRequestHeader().getURI().toString();

	// lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    var contenttype = msg.getResponseHeader().getHeader("Content-Type")
	var unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']
	
	if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
		// if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    		return
	}else{
	// now lets run our regex against the body response
        var body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0 // After testing reset index
            // Look for email addresses
            var foundEmail = []
            var comm
            while (comm = re.exec(body)) {
                foundEmail.push(comm[0]);
            }
		  // woohoo we found an email lets make an alert for it
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundEmail.toString(), alertSolution, '', cweId, wascId, msg);
        }
    }
}
