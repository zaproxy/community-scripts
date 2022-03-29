// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Authorization Bearer Token (script)",
		  "Authorization Basic (script)",
		  "Rails master key Disclosed (script)",
		  "Ruby on rails secrets.yml file Disclosed (script)",
		  "Jetbrains credentials file Disclosed (script)",
		  "PHP configuration file Disclosed (script)",
		  "Apache htpasswd file Disclosed (script)",
		  "Docker configuration file Disclosed (script)",
		  "NPM configuration file Disclosed (script)",
		  "esmtp Configuration Disclosed (script)",
		  "Atom sftp-deployment Config file Disclosed (script)",
		  "Atom remote-sync Config file Disclosed (script)",
		  "WP-Config file Disclosed (script)",
		  "VSCode vscode-sftp file Disclosed (script)",
		  "Docker registry authentication file Disclosed (script)",
		  "SFTP connection configuration file Disclosed (script)",
		  ""]
    var alertDesc = ["An Authorization Bearer Token was discovered.",
		 "Authorization Basic was discovered.",
		 "A Rails master key was discovered.",
		 "A Ruby on rails secrets.yml file was discovered.",
		 "A Jetbrains credentials file was discovered.",
		 "A PHP configuration file was discovered.",
		 "An Apache htpasswd file was discovered.",
		 "A Docker configuration file was discovered.",
		 "A NPM configuration file was discovered.",
		 "An esmtp Configuration was discovered.",
		 "An Atom sftp-deployment Config file was discovered.",
		 "An Atom remote-sync Config file was discovered.",
		 "A WP-Config file was discovered.",
		 "A VSCode vscode-sftp file was discovered.",
		 "A Docker registry authentication file was discovered.",
		 "An SFTP connection configuration file was discovered.",
		""]
    var alertSolution = ["There might not be an issue here but it's worth checking out. This script finds a few things.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var authbtoken = /(Bearer\s[\d|a-f]{8}-([\d|a-f]{4}-){3}[\d|a-f]{12}|Bearer\s[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+(\.[A-Za-z0-9\-_.+/=]+)?)/g
    var authbasictoken = /(Basic\s[a-zA-Z0-9+\/]+\=*)/g
    var railsmkey = /(ruby\/config\/master\.key)/g
    var rubysfile = /(web\/ruby\/secrets\.yml)/g
    var jbrainsxml = /(\.?idea\/WebServers\.xml)/g
    var phpconfigfile = /(config(\.inc)?\.php)/g
    var htpasswdfile = /(\.?htpasswd)/g
    var dockerconfigfile = /(\.?dockercfg)/g
    var npmconfig = /(\.?npmrc)/g
	var esmtpconfig = /(\.esmtprc)/g
	var atomsftpdeployment = /((deployment-config(\.json)?|\.ftpconfig))/g
	var atomsremotesync = /(\.remote-sync.json)/g
	var wpconfigfile = /(define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]")/g
	var vscodesftpfile = /(\.?vscode\/sftp\.json)/g
	var dockerregistryauth = /(\.?docker\/config\.json)/g
	var sftpconfig = /(sftp-config(\.json)?)/g

	if (authbtoken.test(body))
	  {
	    authbtoken.lastIndex = 0
	    var foundauthbtoken = []
	    var comm
            while (comm = authbtoken.exec(body))
	      {
               foundauthbtoken.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundauthbtoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (authbasictoken.test(body))
	  {
	    authbasictoken.lastIndex = 0
	    var foundauthbasictoken = []
            while (comm = authbasictoken.exec(body))
	      {
               foundauthbasictoken.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundauthbasictoken.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (railsmkey.test(body))
	  {
	    railsmkey.lastIndex = 0
	    var foundrailsmkey = []
            while (comm = railsmkey.exec(body))
	      {
               foundrailsmkey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundrailsmkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (rubysfile.test(body))
	  {
	    rubysfile.lastIndex = 0
	    var foundrubysfile = []
            while (comm = rubysfile.exec(body))
	      {
               foundrubysfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundrubysfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (jbrainsxml.test(body))
	  {
	    jbrainsxml.lastIndex = 0
	    var foundjbrainsxml = []
            while (comm = jbrainsxml.exec(body))
	      {
               foundjbrainsxml.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundjbrainsxml.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (phpconfigfile.test(body))
	  {
	    phpconfigfile.lastIndex = 0
	    var foundphpconfigfile = []
            while (comm = phpconfigfile.exec(body))
	      {
               foundphpconfigfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundphpconfigfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (htpasswdfile.test(body))
	  {
	    htpasswdfile.lastIndex = 0
	    var foundhtpasswdfile = []
            while (comm = htpasswdfile.exec(body))
	      {
               foundhtpasswdfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundhtpasswdfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (dockerconfigfile.test(body))
	  {
	    dockerconfigfile.lastIndex = 0
	    var founddockerconfigfile = []
            while (comm = dockerconfigfile.exec(body))
	      {
               founddockerconfigfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', founddockerconfigfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (npmconfig.test(body))
	  {
	    npmconfig.lastIndex = 0
	    var foundnpmconfig = []
            while (comm = npmconfig.exec(body))
	      {
               foundnpmconfig.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[1], alertTitle[8], alertDesc[8], url, '', '', foundnpmconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (esmtpconfig.test(body))
	  {
	    esmtpconfig.lastIndex = 0
	    var foundesmtpconfig = []
            while (comm = esmtpconfig.exec(body))
	      {
               foundesmtpconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[9], alertDesc[9], url, '', '', foundesmtpconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (atomsftpdeployment.test(body))
	  {
	    atomsftpdeployment.lastIndex = 0
	    var foundatomsftpdeployment = []
            while (comm = atomsftpdeployment.exec(body))
	      {
               foundatomsftpdeployment.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[10], alertDesc[10], url, '', '', foundatomsftpdeployment.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (atomsremotesync.test(body))
	  {
	    atomsremotesync.lastIndex = 0
	    var foundatomsremotesync = []
            while (comm = atomsremotesync.exec(body))
	      {
               foundatomsremotesync.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[11], alertDesc[11], url, '', '', foundatomsremotesync.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (wpconfigfile.test(body))
	  {
	    wpconfigfile.lastIndex = 0
	    var foundwpconfigfile = []
            while (comm = wpconfigfile.exec(body))
	      {
               foundwpconfigfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[12], alertDesc[12], url, '', '', foundwpconfigfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (vscodesftpfile.test(body))
	  {
	    vscodesftpfile.lastIndex = 0
	    var foundvscodesftpfile = []
            while (comm = vscodesftpfile.exec(body))
	      {
               foundvscodesftpfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[13], alertDesc[13], url, '', '', foundvscodesftpfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (dockerregistryauth.test(body))
	  {
	    dockerregistryauth.lastIndex = 0
	    var founddockerregistryauth = []
            while (comm = dockerregistryauth.exec(body))
	      {
               founddockerregistryauth.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[14], alertDesc[14], url, '', '', founddockerregistryauth.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sftpconfig.test(body))
	  {
	    sftpconfig.lastIndex = 0
	    var foundsftpconfig = []
            while (comm = sftpconfig.exec(body))
	      {
               foundsftpconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[15], alertDesc[15], url, '', '', foundsftpconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
