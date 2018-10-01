// Cookie HttpOnly Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    var alertRisk = 1
    var alertReliability = 2
    var alertTitle = "Cookie set without HTTPOnly Flag(script)"
    var alertDesc = "A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible."
    var alertSolution = "Ensure that the HttpOnly flag is set for all cookies."

    var cweId = 0
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("Set-Cookie")
    
    if (headers != null)
    {
        var re_noflag = /([Hh][Tt][Tt][Pp][Oo][Nn][Ll][Yy])/g
        if (!(re_noflag.test(headers)))
        {
            ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
        }
    }
    
}
