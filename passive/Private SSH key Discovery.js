// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp, regex shamelessly ripped from https://github.com/CYS4srl/CYS4-SensitiveDiscoverer

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["Private SSH key Disclosed (script)",
		  ""]
    var alertDesc = ["A Private SSH key was discovered.",
		""]
    var alertSolution = ["Store SSH Private keys in a secure location.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var privatesshkey = /(^.*_rsa|^.*_dsa|^.*_ed25519|^.*_ecdsa|-----BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY)/g

	if (privatesshkey.test(body))
	  {
	    privatesshkey.lastIndex = 0
	    var foundprivatesshkey = []
	    var comm
            while (comm = privatesshkey.exec(body))
	      {
               foundprivatesshkey.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundprivatesshkey.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
