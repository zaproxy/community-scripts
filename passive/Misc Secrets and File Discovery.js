// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["SSH configuration file Disclosed (script)",
		  "Potential cryptographic private key Disclosed (script)",
		  "Ruby IRB console history file Disclosed (script)",
		  "GNOME Keyring database file Disclosed (script)",
		  "Configuration file for auto-login process Disclosed (script)",
		  "Rubygems credentials file Disclosed (script)",
		  "git-credential-store helper credentials file Disclosed (script)",
		  "Git configuration file Disclosed (script)",
		  "Chef private key Disclosed (script)",
		  "Potential Linux shadow file Disclosed (script)",
		  "Potential Linux passwd file Disclosed (script)",
		  "Environment configuration file Disclosed (script)",
		  "SSH Password Disclosed (script)",
		  "Firefox saved password collection Disclosed (script)",
		  "KeePass password manager database file Disclosed (script)",
		  ""]
    var alertDesc = ["A SSH configuration file was discovered.",
		 "A Potential cryptographic private key was discovered.",
		 "A Ruby IRB console history file was discovered.",
		 "A GNOME Keyring database file was discovered.",
		 "A Configuration file for auto-login process was discovered.",
		 "A Rubygems credentials file was discovered.",
		 "A git-credential-store helper credentials file was discovered.",
		 "A Git configuration file was discovered.",
		 "A Chef private key was discovered.",
		 "A Potential Linux shadow file was discovered",
		 "A Potential Linux passwd file was discovered",
		 "An Environment configuration file was discovered",
		 "An SSH Password was discovered",
		 "A Firefox saved password collection was discovered",
		 "A KeePass password manager database file was discovered.",
		""]
    var alertSolution = ["Ensure configuration files that are publically accessible are not sensitive in nature.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var sshconfig = /(\.?ssh\/config$)/g
    var possprivatekey = /(^key(pair)?$)/g
    var rubyirb = /((\.)?irb_history)/g
    var gnomekeyring = /(key(store|ring)[\W]+)/g
    var netrcconfig = /((\.|_)?netrc)/g
    var rubygemsconfig = /(\.?gem\/credentials)/g
    var gitcredstorehelper = /(\.?git-credentials)/g
	var gitconfigfile = /(\.?gitconfig)/g
	var chefprivatekey = /(\.?chef\/(.*)\.pem)/g
    var linuxshadow = /(etc\/shadow)/g
	var linuxpasswd = /(etc\/passwd)/g
	var envconfigfile = /(\.env)/g
	var sshpasswd = /(sshpass -p .*['|\\\\"])/g
	var firefoxpasswd = /(\.?mozilla[\\\/]firefox[\\\/]logins\.json)/g
	var keepassdb = /(\.kdbx?)/g

	if (sshconfig.test(body))
	  {
	    sshconfig.lastIndex = 0
	    var foundsshconfig = []
	    var comm
            while (comm = sshconfig.exec(body))
	      {
               foundsshconfig.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundsshconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (possprivatekey.test(body))
	  {
	    possprivatekey.lastIndex = 0
	    var foundpossprivatekey = []
            while (comm = possprivatekey.exec(body))
	      {
               foundpossprivatekey.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundpossprivatekey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (rubyirb.test(body))
	  {
	    rubyirb.lastIndex = 0
	    var foundrubyirb = []
            while (comm = rubyirb.exec(body))
	      {
               foundrubyirb.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundrubyirb.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (gnomekeyring.test(body))
	  {
	    gnomekeyring.lastIndex = 0
	    var foundgnomekeyring = []
            while (comm = gnomekeyring.exec(body))
	      {
               foundgnomekeyring.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundgnomekeyring.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (netrcconfig.test(body))
	  {
	    netrcconfig.lastIndex = 0
	    var foundnetrcconfig = []
            while (comm = netrcconfig.exec(body))
	      {
               foundnetrcconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[4], alertDesc[4], url, '', '', foundnetrcconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (rubygemsconfig.test(body))
	  {
	    rubygemsconfig.lastIndex = 0
	    var foundrubygemsconfig = []
            while (comm = rubygemsconfig.exec(body))
	      {
               foundrubygemsconfig.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[5], alertDesc[5], url, '', '', foundrubygemsconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (gitcredstorehelper.test(body))
	  {
	    gitcredstorehelper.lastIndex = 0
	    var foundgitcredstorehelper = []
            while (comm = gitcredstorehelper.exec(body))
	      {
               foundgitcredstorehelper.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[6], alertDesc[6], url, '', '', foundgitcredstorehelper.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (gitconfigfile.test(body))
	  {
	    gitconfigfile.lastIndex = 0
	    var foundgitconfigfile = []
            while (comm = gitconfigfile.exec(body))
	      {
               foundgitconfigfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[7], alertDesc[7], url, '', '', foundgitconfigfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (chefprivatekey.test(body))
	  {
	    chefprivatekey.lastIndex = 0
	    var foundchefprivatekey = []
            while (comm = chefprivatekey.exec(body))
	      {
               foundchefprivatekey.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[8], alertDesc[8], url, '', '', foundchefprivatekey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
    if (linuxshadow.test(body))
	  {
	    linuxshadow.lastIndex = 0
	    var foundlinuxshadow = []
            while (comm = linuxshadow.exec(body))
	      {
               foundlinuxshadow.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[9], alertDesc[9], url, '', '', foundlinuxshadow.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (linuxpasswd.test(body))
	  {
	    linuxpasswd.lastIndex = 0
	    var foundlinuxpasswd = []
            while (comm = linuxpasswd.exec(body))
	      {
               foundlinuxpasswd.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[10], alertDesc[10], url, '', '', foundlinuxpasswd.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (envconfigfile.test(body))
	  {
	    envconfigfile.lastIndex = 0
	    var foundenvconfigfile = []
            while (comm = envconfigfile.exec(body))
	      {
               foundenvconfigfile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[11], alertDesc[11], url, '', '', foundenvconfigfile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (sshpasswd.test(body))
	  {
	    sshpasswd.lastIndex = 0
	    var foundsshpasswd = []
            while (comm = sshpasswd.exec(body))
	      {
               foundsshpasswd.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[12], alertDesc[12], url, '', '', foundsshpasswd.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (firefoxpasswd.test(body))
	  {
	    firefoxpasswd.lastIndex = 0
	    var foundfirefoxpasswd = []
            while (comm = firefoxpasswd.exec(body))
	      {
               foundfirefoxpasswd.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[13], alertDesc[13], url, '', '', foundfirefoxpasswd.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (keepassdb.test(body))
	  {
	    keepassdb.lastIndex = 0
	    var foundkeepassdb = []
            while (comm = keepassdb.exec(body))
	      {
               foundkeepassdb.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[14], alertDesc[14], url, '', '', foundkeepassdb.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
