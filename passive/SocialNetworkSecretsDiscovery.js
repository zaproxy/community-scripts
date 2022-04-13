// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Facebook Secret Key Disclosed (script)",
		  "Facebook Client ID Disclosed (script)",
		  "Twitter Secret Key Disclosed (script)",
		  "Twitter Client ID Disclosed (script)",
		  "Twitter Access Token Disclosed (script)",
		  "Twitter OAuth Disclosed (script)",
		  "Linkedin Client ID Disclosed (script)",
		  "LinkedIn Secret Key Disclosed (script)",
		  "Facebook OAuth Disclosed (script)",
		  "Facebook access token Disclosed (script)",
		  ""]
    var alertDesc = ["A Facebook Secret Key was discovered.",
		 "A Facebook Client ID was discovered.",
		 "A Twitter Secret Key was discovered.",
		 "A Twitter Client ID was discovered.",
		 "A Twitter Access Token was discovered.",
		 "A Twitter OAuth was discovered.",
		 "A Linkedin Client ID was discovered.",
		 "A LinkedIn Secret Key was discovered.",
		 "A Facebook OAuth was discovered.",
		 "A Facebook access token was discovered.",
		""]
    var alertSolution = ["Ensure tokens and keys that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var fbsecretkey = /((\i)(facebook|fb)(.{0,20})?(\-i)['\"][0-9a-f]{32}['\"])/g
    var fbclientid = /((\i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"])/g
    var twsecretkey = /((\i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"])/g
    var twclientid = /((\i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"])/g
    var twaccesstoken = /([t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40})/g
    var twoauth = /([t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"])/g
    var lkdinclientid = /((\i)linkedin(.{0,20})?(\-i)['\"][0-9a-z]{12}['\"])/g
    var lkdinsecretkey = /((\i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"])/g
	var fboauth = /([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"])/g
	var fbaccesstoken = /(EAACEdEose0cBA[0-9A-Za-z]+)/g

	if (fbsecretkey.test(body))
	  {
	    fbsecretkey.lastIndex = 0
	    var foundfbsecretkey = []
	    var comm
            while (comm = fbsecretkey.exec(body))
	      {
               foundfbsecretkey.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundfbsecretkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (fbclientid.test(body))
	  {
	    fbclientid.lastIndex = 0
	    var foundfbclientid = []
            while (comm = fbclientid.exec(body))
	      {
               foundfbclientid.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundfbclientid.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (twsecretkey.test(body))
	  {
	    twsecretkey.lastIndex = 0
	    var foundtwsecretkey = []
            while (comm = twsecretkey.exec(body))
	      {
               foundtwsecretkey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundtwsecretkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (twclientid.test(body))
	  {
	    twclientid.lastIndex = 0
	    var foundtwclientid = []
            while (comm = twclientid.exec(body))
	      {
               foundtwclientid.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundtwclientid.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (twaccesstoken.test(body))
	  {
	    twaccesstoken.lastIndex = 0
	    var foundtwaccesstoken = []
            while (comm = twaccesstoken.exec(body))
	      {
               foundtwaccesstoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundtwaccesstoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (twoauth.test(body))
	  {
	    twoauth.lastIndex = 0
	    var foundtwoauth = []
            while (comm = twoauth.exec(body))
	      {
               foundtwoauth.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundtwoauth.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (lkdinclientid.test(body))
	  {
	    lkdinclientid.lastIndex = 0
	    var foundlkdinclientid = []
            while (comm = lkdinclientid.exec(body))
	      {
               foundlkdinclientid.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundlkdinclientid.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (lkdinsecretkey.test(body))
	  {
	    lkdinsecretkey.lastIndex = 0
	    var foundlkdinsecretkey = []
            while (comm = lkdinsecretkey.exec(body))
	      {
               foundlkdinsecretkey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', foundlkdinsecretkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (fboauth.test(body))
	  {
	    fboauth.lastIndex = 0
	    var foundfboauth = []
            while (comm = fboauth.exec(body))
	      {
               foundfboauth.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[8], alertDesc[8], url, '', '', foundfboauth.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (fbaccesstoken.test(body))
	  {
	    fbaccesstoken.lastIndex = 0
	    var foundfbaccesstoken = []
            while (comm = fbaccesstoken.exec(body))
	      {
               foundfbaccesstoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[9], alertDesc[9], url, '', '', foundfbaccesstoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
