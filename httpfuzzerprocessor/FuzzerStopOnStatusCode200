/**
 * Processes the fuzzed message (payloads already injected).
 * 
 * Called before forwarding the message to the server.
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpMessage} message - The fuzzed message, that will be forward to the server.
 */
function processMessage(utils, message) {
}

/**
 * Processes the fuzz result.
 * 
 * Called after receiving the fuzzed message from the server.
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpFuzzResult} fuzzResult - The result of sending the fuzzed message.
 * @return {boolean} Whether the result should be accepted, or discarded and not shown.
 */
function processResult(utils, fuzzResult){
	if (fuzzResult.getHttpMessage().getResponseHeader().getStatusCode() == 200)
		utils.stopFuzzer();
	return true;
}
