// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp, regex shamelessly ripped from https://github.com/CYS4srl/CYS4-SensitiveDiscoverer

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["DigitalOcean doctl command-line client configuration file Disclosed (script)",
		  "Tugboat DigitalOcean management tool configuration Disclosed (script)",
		  "GitHub Hub command-line client configuration file Disclosed (script)",
		  "Firebase URL Disclosed (script)",
		  "GitHub stuff Disclosed (script)",
		  "Generic Secret Disclosed (script)",
		  "IP Address Disclosed (script)",
		  "Slack Token Disclosed (script)",
		  "Slack Webhook Disclosed (script)",
		  "Outlook Team Webhook Disclosed (script)",
		  "Artifactory stuff Disclosed (script)",
		  "CodeClimate stuff Disclosed (script)",
		  "Sauce Token Disclosed (script)",
		  "Github Key Disclosed (script)",
		  "Heroku Key Disclosed (script)",
		  "Splunk Authorization Disclosed (script)",
		  "Square Access Token Disclosed (script)",
		  "Square OAuth Secret Disclosed (script)",
		  "PayPal/Braintree Access Token Disclosed (script)",
		  ""]
    var alertDesc = ["A DigitalOcean doctl command-line client configuration file was discovered.",
		 "A Tugboat DigitalOcean management tool configuration was discovered.",
		 "A GitHub Hub command-line client configuration file was discovered.",
		 "A Firebase URL was discovered.",
		 "GitHub stuff was discovered.",
		 "A Generic Secret was discovered.",
		 "An IP Address was discovered.",
		 "A Slack Token was discovered.",
		 "A Slack Webhook was discovered.",
		 "An Outlook Team Webhook was discovered.",
		 "Artifactory stuff was discovered",
		 "CodeClimate stuff was discovered",
		 "A Sauce Token was discovered",
		 "A Github Key was discovered",
		 "A Heroku Key was discovered",
		 "Splunk Authorization was discovered",
		 "A Square Access Token was discovered",
		 "A Square OAuth Secret was discovered",
		 "A PayPal/Braintree Access Token was discovered",
		""]
    var alertSolution = ["Ensure API keys, Tokens and configuration files that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var doctlcliconfig = /(doctl\/config\.yaml)/g
    var dotugboat = /(\.?tugboat)/g
    var githubhub = /(config\/hub)/g
    var firebaseurl = /([a-z0-9.-]+\.firebaseio\.com)/g
    var githubstuff = /([g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"])/g
    var genericsecret = /([s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"])/g
    var ipaddress = /([^\.0-9](([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[^\.0-9])/g
	var slacktoken = /((xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}))/g
	var slackwebhook = /(https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24})/g
    var outlookwebhook = /(https:\/\/outlook\\\.office\\\.com\/webhook\/[0-9a-f-]{36}@)/g
	var artifactorystuff = /((?i)artifactory.{0,50}(\"|'|`)?[a-zA-Z0-9=]{112}(\"|'|`)?)/g
	var codeclimatestuff = /((?i)codeclima.{0,50}(\"|'|`)?[0-9a-f]{64}(\"|'|`)?)/g
	var saucetoken = /((?i)sauce.{0,50}(\"|'|`)?[0-9a-f-]{36}(\"|'|`)?)/g
	var githubkey = /((?i)github(.{0,20})?(?-i)[''\"][0-9a-zA-Z]{35,40}[''\"])/g
	var herokukey = /((?i)heroku(.{0,20})?[''\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[''\"])/g
	var splunkauth = /(Splunk\s(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1})/g
	var squareaccesstoken = /(sq0atp-[0-9A-Za-z\-_]{22})/g
	var squareoauthsecret = /(sq0csp-[0-9A-Za-z\-_]{43})/g
	var paypalaccesstoken = /(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})/g

	if (doctlcliconfig.test(body))
	  {
	    doctlcliconfig.lastIndex = 0
	    var founddoctlcliconfig = []
	    var comm
            while (comm = doctlcliconfig.exec(body))
	      {
               founddoctlcliconfig.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', founddoctlcliconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (dotugboat.test(body))
	  {
	    dotugboat.lastIndex = 0
	    var founddotugboat = []
            while (comm = dotugboat.exec(body))
	      {
               founddotugboat.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', founddotugboat.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (githubhub.test(body))
	  {
	    githubhub.lastIndex = 0
	    var foundgithubhub = []
            while (comm = githubhub.exec(body))
	      {
               foundgithubhub.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundgithubhub.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (firebaseurl.test(body))
	  {
	    firebaseurl.lastIndex = 0
	    var foundfirebaseurl = []
            while (comm = firebaseurl.exec(body))
	      {
               foundfirebaseurl.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundfirebaseurl.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (githubstuff.test(body))
	  {
	    githubstuff.lastIndex = 0
	    var foundgithubstuff = []
            while (comm = githubstuff.exec(body))
	      {
               foundgithubstuff.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundgithubstuff.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (genericsecret.test(body))
	  {
	    genericsecret.lastIndex = 0
	    var foundgenericsecret = []
            while (comm = genericsecret.exec(body))
	      {
               foundgenericsecret.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundgenericsecret.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (ipaddress.test(body))
	  {
	    ipaddress.lastIndex = 0
	    var foundipaddress = []
            while (comm = ipaddress.exec(body))
	      {
               foundipaddress.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundipaddress.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (slacktoken.test(body))
	  {
	    slacktoken.lastIndex = 0
	    var foundslacktoken = []
            while (comm = slacktoken.exec(body))
	      {
               foundslacktoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', foundslacktoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (slackwebhook.test(body))
	  {
	    slackwebhook.lastIndex = 0
	    var foundslackwebhook = []
            while (comm = slackwebhook.exec(body))
	      {
               foundslackwebhook.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[8], alertDesc[8], url, '', '', foundslackwebhook.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
    if (outlookwebhook.test(body))
	  {
	    outlookwebhook.lastIndex = 0
	    var foundoutlookwebhook = []
            while (comm = outlookwebhook.exec(body))
	      {
               foundoutlookwebhook.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[9], alertDesc[9], url, '', '', foundoutlookwebhook.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (artifactorystuff.test(body))
	  {
	    artifactorystuff.lastIndex = 0
	    var foundartifactorystuff = []
            while (comm = artifactorystuff.exec(body))
	      {
               foundartifactorystuff.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[10], alertDesc[10], url, '', '', foundartifactorystuff.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (codeclimatestuff.test(body))
	  {
	    codeclimatestuff.lastIndex = 0
	    var foundcodeclimatestuff = []
            while (comm = codeclimatestuff.exec(body))
	      {
               foundcodeclimatestuff.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[11], alertDesc[11], url, '', '', foundcodeclimatestuff.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (saucetoken.test(body))
	  {
	    saucetoken.lastIndex = 0
	    var foundsaucetoken = []
            while (comm = saucetoken.exec(body))
	      {
               foundsaucetoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[12], alertDesc[12], url, '', '', foundsaucetoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (githubkey.test(body))
	  {
	    githubkey.lastIndex = 0
	    var foundgithubkey = []
            while (comm = githubkey.exec(body))
	      {
               foundgithubkey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[13], alertDesc[13], url, '', '', foundgithubkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (herokukey.test(body))
	  {
	    herokukey.lastIndex = 0
	    var foundherokukey = []
            while (comm = herokukey.exec(body))
	      {
               foundherokukey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[14], alertDesc[14], url, '', '', foundherokukey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (splunkauth.test(body))
	  {
	    splunkauth.lastIndex = 0
	    var foundsplunkauth = []
            while (comm = splunkauth.exec(body))
	      {
               foundsplunkauth.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[15], alertDesc[15], url, '', '', foundsplunkauth.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (squareaccesstoken.test(body))
	  {
	    squareaccesstoken.lastIndex = 0
	    var foundsquareaccesstoken = []
            while (comm = squareaccesstoken.exec(body))
	      {
               foundsquareaccesstoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[16], alertDesc[16], url, '', '', foundsquareaccesstoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (squareoauthsecret.test(body))
	  {
	    squareoauthsecret.lastIndex = 0
	    var foundsquareoauthsecret = []
            while (comm = squareoauthsecret.exec(body))
	      {
               foundsquareoauthsecret.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[17], alertDesc[17], url, '', '', foundsquareoauthsecret.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (paypalaccesstoken.test(body))
	  {
	    paypalaccesstoken.lastIndex = 0
	    var foundpaypalaccesstoken = []
            while (comm = paypalaccesstoken.exec(body))
	      {
               foundpaypalaccesstoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[18], alertDesc[18], url, '', '', foundpaypalaccesstoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
