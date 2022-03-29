// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Stripe API key Disclosed (script)",
		  "Recon-ng web reconnaissance framework API key database Disclosed (script)",
		  "Generic API Key Disclosed (script)",
		  "Google Cloud API Key Disclosed (script)",
		  "Picatic API key Disclosed (script)",
		  "Twilio API Key Disclosed (script)",
		  "SendGrid API Key Disclosed (script)",
		  "MailGun API Key Disclosed (script)",
		  "MailChimp API Key Disclosed (script)",
		  "NuGet API Key Disclosed (script)",
		  "SonarQube Docs API Key Disclosed (script)",
		  "StackHawk API Key Disclosed (script)",
		  ""]
    var alertDesc = ["A Stripe API key was discovered.",
		 "A Recon-ng web reconnaissance framework API key database was discovered.",
		 "A Generic API Key was discovered.",
		 "A Google Cloud API Key was discovered.",
		 "A Picatic API key was discovered.",
		 "A Twilio API Key was discovered.",
		 "A SendGrid API Key was discovered.",
		 "A MailGun API Key was discovered.",
		 "A MailChimp API Key was discovered.",
		 "A NuGet API Key was discovered.",
		 "A SonarQube Docs API Key was discovered.",
		 "A StackHawk API Key was discovered.",
		""]
    var alertSolution = ["Ensure API keys that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var stripe = /((?:r|p|s)k_(live|test)_[0-9a-zA-Z]{24})/g
    var reconng = /(\.?recon-ng\/keys\.db)/g
    var generic = /([a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"])/g
    var googlecloud = /(AIza[0-9A-Za-z\-_]{35})/g
    var picatic = /(sk_(live|test)_[0-9a-z]{32})/g
    var twilio = /(SK[0-9a-fA-F]{32})/g
    var sendgrid = /(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})/g
    var mailgun = /(key-[0-9a-zA-Z]{32})/g
    var mailchimp = /([0-9a-f]{32}-us[0-9]{12})/g
	var nuget = /(oy2[a-z0-9]{43})/g
	var sonarqube = /((?i)sonar.{0,50}(\"|'|`)?[0-9a-f]{40}(\"|'|`)?)/g
	var stackhawk = /(hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20})/g

	if (stripe.test(body))
	  {
	    stripe.lastIndex = 0
	    var foundstripe = []
	    var comm
            while (comm = stripe.exec(body))
	      {
               foundstripe.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundstripe.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (reconng.test(body))
	  {
	    reconng.lastIndex = 0
	    var foundreconng = []
            while (comm = reconng.exec(body))
	      {
               foundreconng.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundreconng.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (generic.test(body))
	  {
	    generic.lastIndex = 0
	    var foundgeneric = []
            while (comm = generic.exec(body))
	      {
               foundgeneric.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundgeneric.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (googlecloud.test(body))
	  {
	    googlecloud.lastIndex = 0
	    var foundgooglecloud = []
            while (comm = googlecloud.exec(body))
	      {
               foundgooglecloud.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundgooglecloud.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (picatic.test(body))
	  {
	    picatic.lastIndex = 0
	    var foundpicatic = []
            while (comm = picatic.exec(body))
	      {
               foundpicatic.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundpicatic.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (twilio.test(body))
	  {
	    twilio.lastIndex = 0
	    var foundtwilio = []
            while (comm = twilio.exec(body))
	      {
               foundtwilio.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundtwilio.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sendgrid.test(body))
	  {
	    sendgrid.lastIndex = 0
	    var foundsendgrid = []
            while (comm = sendgrid.exec(body))
	      {
               foundsendgrid.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundsendgrid.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (mailgun.test(body))
	  {
	    mailgun.lastIndex = 0
	    var foundmailgun = []
            while (comm = mailgun.exec(body))
	      {
               foundmailgun.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', foundmailgun.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (mailchimp.test(body))
	  {
	    mailchimp.lastIndex = 0
	    var foundmailchimp = []
            while (comm = mailchimp.exec(body))
	      {
               foundmailchimp.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[1], alertTitle[8], alertDesc[8], url, '', '', foundmailchimp.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (nuget.test(body))
	  {
	    nuget.lastIndex = 0
	    var foundnuget = []
            while (comm = nuget.exec(body))
	      {
               foundnuget.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[9], alertDesc[9], url, '', '', foundnuget.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sonarqube.test(body))
	  {
	    sonarqube.lastIndex = 0
	    var foundsonarqube = []
            while (comm = sonarqube.exec(body))
	      {
               foundsonarqube.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[10], alertDesc[10], url, '', '', foundsonarqube.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (stackhawk.test(body))
	  {
	    stackhawk.lastIndex = 0
	    var foundstackhawk = []
            while (comm = stackhawk.exec(body))
	      {
               foundstackhawk.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[11], alertDesc[11], url, '', '', foundstackhawk.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
