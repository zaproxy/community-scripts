// IBAN finder by https://renouncedthoughts.wordpress.com
// Heavily inspired by Find Emails.js
// Regex evaluated at https://regexr.com/4kb6e
// Tested against sample vulnerable page https://neverwind.azurewebsites.net/Admin/Download/Get
// Runs as a part of nightly baseline scans in many DevSecOps environments
// Complements the Pluralsight course - Writing Custom Scripts for OWASP Zed Attack Proxy

function scan(ps, msg, src) {
    // first lets set up some details incase we find an IBAN, these will populate the alert later
    var alertRisk = 1
    var alertReliability = 3
    var alertTitle = 'IBAN found - investigation required (script)'
    var alertDesc = 'IBAN numbers were found'
    var alertSolution = 'Investigate IBAN numbers found in the response, remove or mask as required'
    var cweId = 200
    var wascId = 0

    // lets build a regular expression that can find IBAN addresses
    // the regex must appear within /( and )/g
    var re = /([A-Za-z]{2}[0-9]{2}[A-Za-z]{4}[0-9]{10})/g

    // we need to set the url variable to the request or we cant track the alert later
    var url = msg.getRequestHeader().getURI().toString()

    // lets check its not one of the files types that are never likely to contain stuff, like pngs and jpegs
    var contentType = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedFileTypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']

    if (unwantedFileTypes.indexOf(""+contentType) >= 0) {
        // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
        return
	}
    // now lets run our regex against the body response
    var body = msg.getResponseBody().toString()
    if (re.test(body)) {
        re.lastIndex = 0 // After testing reset index
        // Look for IBAN addresses
        var foundIBAN = []
        var comm
        while (comm = re.exec(body)) {
            foundIBAN.push(comm[0]);
        }
    // woohoo we found an IBAN lets make an alert for it
    ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundIBAN.toString(), alertSolution, foundIBAN.toString(), cweId, wascId, msg);
    }
}
