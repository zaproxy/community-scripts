// This script was lazily crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	return true
}

function proxyResponse(msg) {
	var code = msg.getResponseHeader().getStatusCode()
    // You can add more codes here
	if (code == 404 || code == 403 || code == 500 || code == 502) {
		// Drop the response
		return false
	}
	return true
}
