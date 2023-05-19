// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Google OAuth Key Disclosed (script)",
		  "Google OAuth Access Token Disclosed (script)",
		  "Google (GCM) Service account Disclosed (script)",
		  ""]
    var alertDesc = ["A Google OAuth Key was discovered.",
		 "A Google OAuth Access Token was discovered.",
		 "A Google (GCM) Service account was discovered.",
		""]
    var alertSolution = ["Ensure API keys, Tokens and configuration files that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var googleoauthkey = /([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)/g
    var googleoauthaccesstoken = /(ya29\.[0-9A-Za-z\\-_]+)/g
    var googleserviceaccount = /(((\"|'|`)?type(\"|'|`)?\s{0,50}(:|=>|=)\s{0,50}(\"|'|`)?service_account(\"|'|`)?,?))/g

	if (googleoauthkey.test(body))
	  {
	    googleoauthkey.lastIndex = 0
	    var foundgoogleoauthkey = []
	    var comm
            while (comm = googleoauthkey.exec(body))
	      {
               foundgoogleoauthkey.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundgoogleoauthkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (googleoauthaccesstoken.test(body))
	  {
	    googleoauthaccesstoken.lastIndex = 0
	    var foundgoogleoauthaccesstoken = []
            while (comm = googleoauthaccesstoken.exec(body))
	      {
               foundgoogleoauthaccesstoken.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundgoogleoauthaccesstoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (googleserviceaccount.test(body))
	  {
	    googleserviceaccount.lastIndex = 0
	    var foundgoogleserviceaccount = []
            while (comm = googleserviceaccount.exec(body))
	      {
               foundgoogleserviceaccount.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundgoogleserviceaccount.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
