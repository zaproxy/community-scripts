// Server Header Check by freakyclown@gmail.com
// Server Version leaks found via header field by prateek.rana@getastra.com

function scan(ps, msg, src) 
{

    var alertRisk = 1
    var alertConfidence = 2
    var alertTitle = "Server Leaks Version Information via 'Server' HTTP Response Header Field(script)"
    var alertDesc = "The web/application server is leaking version information via the 'Server' HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to."
    var alertSolution = "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details."

    var cweId = 200
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("Server")
    var headers_string = headers.toString();
    
    if (headers != null && ExtAlert(headers))
    {
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', '', alertSolution, headers_string, cweId, wascId, msg);
    }
    
}

function ExtAlert(content) {

    var ext = new RegExp("(\\d+\\.)+\\d+");

    try {
        var res = ext.exec(content);
        if (res == null){
            return false;
        }
        res = res.join('');

        if (res === "") {
            return false;
        }
        
        else {
            print("Server version leak found via header.");
            return true;        
        }
    }

    catch (err) {
        print(err);
        return false;
    }
}
