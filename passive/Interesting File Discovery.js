// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] //1=informational, 2=low, 3=medium, 4=high
    var alertConfidence = [0,1,2,3,4] //0=fp,1=low,2=medium,3=high,4=confirmed
    var alertTitle = ["A file with an interesting extension (script)",
		  ""]
    var alertDesc = ["A file with an interesting extension was discovered.",
		""]
    var alertSolution = ["A file with an interesting extension was discovered. It might be nothing, but it's worth investigating.",
		    ""]
    var cweId = [0,1]
    var wascId = [0,1]

    var interestingext = /(.*\.(pem|log|pkcs12|p12|pfx|asc|otr\.private_key|ovpn|cscfg|rdp|mdf|sdf|sqlite|sqlite3|bek|tpm|fve|jks|psafe3|rb|yml|py|agilekeychain|keychain|pcap|gnucash|xml|kwallet|php|tblk|plist|xpl|dayone|txt|terraform\.tfvars|exports|functions|extra|asa|inc|config|zip|tar|gz|tgz|rar|java|pdf|docx|doc|rtf|xlsx|xls|csv|pptx|ppt|bak|old|tmp|cer|crt|p7b))/g

	if (interestingext.test(body))
	  {
	    interestingext.lastIndex = 0
	    var foundinterestingext = []
	    var comm
            while (comm = interestingext.exec(body))
	      {
               foundinterestingext.push(comm[0]);
	      }
	    ps.raiseAlert(alertRisk[3], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', foundinterestingext.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	  }
}
