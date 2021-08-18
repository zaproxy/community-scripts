/*
 * This fuzz processor script will raise alerts based on HTTP response codes.
 * It expects two special parameters:
 * - A regular expression used to match the response code
 * - A string that is either "pass" or "fail", indicating whether or not a
 *   matching response is expected ("pass") or unexpected ("fail").
 * Unexpected responses will cause an alert to be raised.
 */

// See https://github.com/zaproxy/community-scripts/tree/master/httpfuzzerprocessor

// See https://github.com/zaproxy/community-scripts/blob/master/httpfuzzerprocessor/showDifferences.js
// for inspiration for differencing logic used to document detected defects.

// This script needs Diff add-on

var DiffTool = Java.type("org.zaproxy.zap.extension.diff.diff_match_patch");

/*
 * Declare parameters
 */
function getRequiredParamsNames() {
    return ["pattern", "sense"];
}

function getOptionalParamsNames() {
    return [];
}

/*
 * Processes the fuzzed message (payloads already injected).
 *
 * Called before forwarding the message to the server.
 *
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpMessage} message - The fuzzed message, that will be forward to the server.
 */
function processMessage(utils, message) {
    // Take no action
}

/*
 * Processes the fuzz result.
 *
 * Called after receiving the fuzzed message from the server.
 *
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpFuzzResult} fuzzResult - The result of sending the fuzzed message.
 * @return {boolean} Whether the result should be accepted, or discarded and not shown.
 */
function processResult(utils, fuzzResult) {
    // All the above 'utils' functions are available plus:
    // To raise an alert:
    //    utils.raiseAlert(risk, confidence, name, description)
    // To obtain the fuzzed message, received from the server:
    //    fuzzResult.getHttpMessage()

    // Retrieve (string) parameters and convert to required types
    var params = utils.getParameters();
    var pattern = new RegExp(params.pattern); // response regex
    var sense = params.sense == "pass"; // true if regex is expected response

    // Retrieve response code and test it against supplied pattern
    var fuzzed = fuzzResult.getHttpMessage();
    var actual = fuzzed.getResponseHeader().getStatusCode().toString();
    var found = actual.search(pattern) != -1;
    var expected = found == sense;

    // If unexpected, raise an alert
    if (!expected) {
        // Convert (inverse) of sense to English
        if (sense) { // expected a match but did not get it
            why = " did not match ";
        } else { // expected no match but got one anyway
            why = " matched ";
        }

        // "The original message"
        var original = utils.getOriginalMessage();

        // Compare the content of the original and fuzzed requests; this will
        // indicate what changed to cause the problem. This is very nice if you
        // are sending it somewhere that will render HTML, but looks like noise
        // anywhere else.
        //var diffHtml = createDiffHtml(
        //    requestAsString(original),
        //    requestAsString(fuzzed)
        //);

        // Generate a text difference of the two files
        var diffText = createDiffText(
            requestAsString(original),
            requestAsString(fuzzed)
        );

        utils.raiseAlert(
            3, // High Risk
            2, // Medium Confidence
            "Unexpected Fuzzer Response", // name
            "The application is failing to handle unexpected input correctly.", // description (long)
            null, // what parameter was fuzzed? we have no idea...
            diffText, // attack
            null, // otherInfo (long)
            null, // solution (long)
            null, // reference (long)
            "The received response " + actual + why + params.pattern + ".", // evidence
            684, // CWE-684: Incorrect Provision of Specified Functionality
            20 // WASC-20: Improper Input Handling
        );

        // We don't need any more examples; stop this fuzzer
        utils.stopFuzzer();
    }

    // Always accept the result
    return true;
}

function requestAsString(httpMessage) {
	var requestHeader = httpMessage.getRequestHeader().toString();
	var requestBody = httpMessage.getRequestBody().toString();
	return requestHeader + "\r\n" + requestBody;
}

function createDiffHtml(original, fuzzed) {
    var diffTool = new DiffTool();
    var diffList = diffTool.diff_main(original, fuzzed);
    return diffTool.diff_prettyHtml(diffList);
}

function createDiffText(original, fuzzed) {
    var diffTool = new DiffTool();
    diffTool.Patch_Margin = 16; // bytes of context for patches
    var patchList = diffTool.patch_make(original, fuzzed);
    return diffTool.patch_toText(patchList);
}
