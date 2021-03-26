// X-Powered-By finder by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    var alertRisk = 1
    var alertConfidence = 2
    var alertTitle = "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)(script)"
    var alertDesc = "The web/application server is leaking information via one or more 'X-Powered-By' HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to."
    var alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers."

    var cweId = 200
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("X-Powered-By")
    
    if (headers != null)
    {
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
    }
    
}
