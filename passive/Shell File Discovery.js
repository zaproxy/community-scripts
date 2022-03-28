// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp, regex shamelessly ripped from https://github.com/CYS4srl/CYS4-SensitiveDiscoverer

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Shell command history file Disclosed (script)",
		  "Shell configuration file Disclosed (script)",
		  "Shell profile configuration file Disclosed (script)",
		  "Shell command alias configuration file Disclosed (script)",
		  ""]
    var alertDesc = ["A Shell command history file was discovered.",
		 "A Shell configuration file was discovered.",
		 "A Shell profile configuration file was discovered.",
		 "A Shell command alias configuration file was discovered.",
		""]
    var alertSolution = ["Store Shell files in a secure location.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var shellhistory = /(\.?(bash_|zsh_|sh_|z)+history)/g
    var shellconfig = /(\.?(bash|zsh|csh)rc)/g
    var shellprofile = /(\.?(bash_|zsh_)+profile)/g
    var shellalias = /(\.?(bash_|zsh_)+aliases)/g

	if (shellhistory.test(body))
	  {
	    shellhistory.lastIndex = 0
	    var foundshellhistory = []
	    var comm
            while (comm = shellhistory.exec(body))
	      {
               foundshellhistory.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundshellhistory.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }

	if (shellconfig.test(body))
	  {
	    shellconfig.lastIndex = 0
	    var foundshellconfig = []
            while (comm = shellconfig.exec(body))
	      {
               foundshellconfig.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[1], alertDesc[1], url, '', '', foundshellconfig.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (shellprofile.test(body))
	  {
	    shellprofile.lastIndex = 0
	    var foundshellprofile = []
            while (comm = shellprofile.exec(body))
	      {
               foundshellprofile.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[2], alertDesc[2], url, '', '', foundshellprofile.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
	if (shellalias.test(body))
	  {
	    shellalias.lastIndex = 0
	    var foundshellalias = []
            while (comm = shellalias.exec(body))
	      {
               foundshellalias.push(comm[0]);
	      }
            ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[3], alertDesc[3], url, '', '', foundshellalias.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
