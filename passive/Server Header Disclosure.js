// Server Header Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    var alertRisk = 1
    var alertReliability = 2
    var alertTitle = "Server Leaks Version Information via 'Server' HTTP Response Header Field(script)"
    var alertDesc = "The web/application server is leaking version information via the 'Server' HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to."
    var alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details."

    var cweId = 200
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("Server")
    
    if (headers != null)
    {
        ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
    }
    
}
