// S3 bucket finder by alishasinghania09@gmail.com 

function scan(ps, msg, src) {
    // populate some parameters which will be needed if s3 bucket url is present
    var alertRisk = 1
    var alertReliability = 4
    var alertTitle = 's3 bucket url'
    var alertDesc = 's3 bucket url found in response'
    var alertSolution = 'Remove s3 buckets name from response or make sure the permissions in bucket are configured properly'
    var cweId = 0
    var wascId = 0

    // the regex for s3 bucket url and it must appear within /( and )/g
    var re = /((s3:\\[a-zA-Z0-9-\.\\_]+)|((s3-|s3\.)?(.*)\.amazonaws\.com))/g

    // we need to set the url variable to the request or we cant track the alert later
    var url = msg.getRequestHeader().getURI().toString();

    // If the file type is image jpeg/png , then the scan will be skipped
    var contenttype = msg.getResponseHeader().getHeader("Content-Type")
    var unwantedfiletypes = ['image/png', 'image/jpeg','image/gif','application/x-shockwave-flash','application/pdf']
    if (unwantedfiletypes.indexOf(""+contenttype) >= 0) {
        return
    }
    else{
        // test the regex against the message body
        var body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0 
            var founds3bucket = []
            var comm
            while (comm = re.exec(body)) {
                founds3bucket.push(comm[0]);
            }
            //raise the alert
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', founds3bucket.toString(), alertSolution, '', cweId, wascId, msg);
        }
    }
}

