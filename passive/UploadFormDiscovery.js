// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    var url = msg.getRequestHeader().getURI().toString();
    var body = msg.getResponseBody().toString()
    var alertRisk = [0,1,2,3,4] // risk: 0: info, 1: low, 2: medium, 3: high
    var alertConfidence = [0,1,2,3,4] // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    var alertTitle = ["An upload form appeared! (script)",""]
	var alertDesc = ["An upload form exists. This isn't an issue, but it could be a lot of fun! Go check it out!.",""]
	var alertSolution = ["This isn't an issue, but it could be a lot of fun!",""]
    var cweId = [0,1]
    var wascId = [0,1]
	
	var uploadForm = /(type\s*=\s*['"]?file['"]?)/g
	
	if (uploadForm.test(body))
	{
		uploadForm.lastIndex = 0
		var founduploadForm = []
		var comm
		while (comm = uploadForm.exec(body))
		{
			founduploadForm.push(comm[0]);
		}
		ps.raiseAlert(alertRisk[0], alertConfidence[2], alertTitle[0], alertDesc[0], url, '', '', founduploadForm.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
	}
}
