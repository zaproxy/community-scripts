// Clacks Header Check by freakyclown@gmail.com

function scan(ps, msg, src) 
{

    var alertRisk = 0
    var alertConfidence = 3
    var alertTitle = "Server is running on CLACKS - GNU Terry Pratchett"
    var alertDesc = "The web/application server is running over the CLACKS network, some say its turtles/IP, some says its turtles all the way down the layer stack."
    var alertSolution = "Give the sys admin a high five and rejoice in the disc world."

    var cweId = 200
    var wascId = 13

    var url = msg.getRequestHeader().getURI().toString();
    var headers = msg.getResponseHeader().getHeaders("X-Clacks-Overhead")
    
    if (headers != null)
    {
        ps.raiseAlert(alertRisk, alertConfidence, alertTitle, alertDesc, url, '', '', '', alertSolution,headers, cweId, wascId, msg);
    }
    
}
