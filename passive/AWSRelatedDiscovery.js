// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["AWS CLI credentials file Disclosed (script)",
		  "AWS Access Key ID Value Disclosed (script)",
		  "AWS ARN Disclosed (script)",
		  "AWS Secret Access Key Disclosed (script)",
		  "AWS Session Token Disclosed (script)",
		  "AWS credential file Disclosed (script)",
		  "Amazon MWS Auth Token Disclosed (script)",
		  "S3cmd configuration file Disclosed (script)",
		  ""]
    var alertDesc = ["An AWS CLI credentials file was discovered.",
		 "An AWS Access Key ID Value was discovered.",
		 "An AWS ARN was discovered.",
		 "An AWS Secret Access Key was discovered.",
		 "An AWS Session Token was discovered.",
		 "An AWS credential file was discovered.",
		 "An Amazon MWS Auth Token was discovered.",
		 "An S3cmd configuration file was discovered.",
		""]
    var alertSolution = ["Ensure API keys, Tokens and configuration files that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

	var awsclicreds = /\.?aws\/credentials/g;
	var awsaccesskeyid = /((A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}|[A-Z0-9]{20})/g;
	var awsarn = /arn:aws:organizations::\d{12}:account\/o-[a-z0-9]{10,32}\/\d{12}/g;
	var awssecretskey = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g;
	var awssessiontoken = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{16,}(?<![A-Za-z0-9/+=])/g;
	var awscredfile = /(?i)(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}/g;
	var amazonmws = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
	var s3cmdconfig = /\.?s3cfg/g;

	if (awsclicreds.test(body))
	  {
	    awsclicreds.lastIndex = 0
	    var foundawsclicreds = []
	    var comm
            while (comm = awsclicreds.exec(body))
	      {
               foundawsclicreds.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundawsclicreds.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (awsaccesskeyid.test(body))
	  {
	    awsaccesskeyid.lastIndex = 0
	    var foundawsaccesskeyid = []
            while (comm = awsaccesskeyid.exec(body))
	      {
               foundawsaccesskeyid.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundawsaccesskeyid.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (awsarn.test(body))
	  {
	    awsarn.lastIndex = 0
	    var foundawsarn = []
            while (comm = awsarn.exec(body))
	      {
               foundawsarn.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundawsarn.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (awssecretskey.test(body))
	  {
	    awssecretskey.lastIndex = 0
	    var foundawssecretskey = []
            while (comm = awssecretskey.exec(body))
	      {
               foundawssecretskey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundawssecretskey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (awssessiontoken.test(body))
	  {
	    awssessiontoken.lastIndex = 0
	    var foundawssessiontoken = []
            while (comm = awssessiontoken.exec(body))
	      {
               foundawssessiontoken.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundawssessiontoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (awscredfile.test(body))
	  {
	    awscredfile.lastIndex = 0
	    var foundawscredfile = []
            while (comm = awscredfile.exec(body))
	      {
               foundawscredfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundawscredfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (amazonmws.test(body))
	  {
	    amazonmws.lastIndex = 0
	    var foundamazonmws = []
            while (comm = amazonmws.exec(body))
	      {
               foundamazonmws.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundamazonmws.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (s3cmdconfig.test(body))
	  {
	    s3cmdconfig.lastIndex = 0
	    var founds3cmdconfig = []
            while (comm = s3cmdconfig.exec(body))
	      {
               founds3cmdconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', founds3cmdconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
