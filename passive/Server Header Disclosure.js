// Server Header Check by freakyclown@gmail.com
// Server Version leaks found via header field by prateek.rana@getastra.com

var VERSION_PATTERN = new RegExp("(?:\\d+\\.)+\\d+");

function scan(ps, msg, src)  {

    var alertRisk = 1
    var alertConfidence = 2
    var alertTitle = "Server Leaks Version Information via 'Server' HTTP Response Header Field(script)"
    var alertDesc = "The web/application server is leaking version information via the 'Server' HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to."
    var alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details."

    var cweId = 200
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("Server")
    
    if (headers != null && containsPotentialSemver(headers))
    {
        var headersString = headers.toString();
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', '', alertSolution, headersString, cweId, wascId, msg);
    }
    
}

function containsPotentialSemver(content) {
    try {
        var res = VERSION_PATTERN.exec(content);
        if (res == null || res.join('') === ""){
            return false;
        }
        return true;
    }

    catch (err) {
        return false;
    }
}
