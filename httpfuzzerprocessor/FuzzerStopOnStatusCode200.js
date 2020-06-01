function processMessage(utils, message) {
}

function processResult(utils, fuzzResult){
	if (fuzzResult.getHttpMessage().getResponseHeader().getStatusCode() == 200)
		utils.stopFuzzer();
	return true;
}
