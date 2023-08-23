//Passive scan for Java error messages containing sensitive information (CWE-209)

function scan(ps, msg, src) {
    var alertRisk = 2
    var alertConfidence = 3
    var alertTitle = 'Java stack trace disclosure (or similar) - investigation required (script)'
    var alertDesc = 'Java stack trace disclosure (or similar) was found'
    var alertSolution = 'Investigate Java stack trace disclosures found in the response, remove or mask as required'
    var cweId = 209
    var wascId = 0

    var re = /springframework|\.java|rootBeanClass/i

    var url = msg.getRequestHeader().getURI().toString()

    var contentType = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedFileTypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']

    if (unwantedFileTypes.indexOf(""+contentType) >= 0) {
        return
    }

    var body = msg.getResponseBody().toString()
    if (re.test(body)) {
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', body, alertSolution, body, cweId, wascId, msg)
        //console.log("Java leak detected");
    }

}
