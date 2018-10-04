// If you need to replace two sections with the same fuzzer value
// you can use `__x1__` as a template tag that is replaced with
// the matching fuzz payload location
var count = 1;
var HttpRequestBody = Java.type('org.zaproxy.zap.network.HttpRequestBody');

function replacePayloads(str, patterns) {
  for (var i in patterns) {
    var rex = patterns[i][0];
    var replacment = patterns[i][1]; 
    str = str.replace(rex, replacment);
  }
  return str;
}

/**
 * Processes the fuzzed message (payloads already injected).
 * Called before forwarding the message to the server.
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpMessage} message - The fuzzed message, that will be forward to the server.
 */
function processMessage(utils, message) {
  var payloads = utils.getPayloads();
  var patterns = [];

  for (var i in payloads) {
    patterns.push(new RegExp('__x' + (i+1) + '__', 'g'), payloads[i]);
  }

  var header = message.getRequestHeader();
  var headers = header.getHeaders();

  for (var i in headers) {
    var adjusted = replacePayloads(headers[i].getValue(), patterns);
    header.setHeader(headers[i].getName(), adjusted);
  }

  var path = replacePayloads(header.getURI().getPath(), patterns);
  var qry  = replacePayloads((header.getURI().getQuery() || ''), patterns);
  var body = replacePayloads(message.getRequestBody().toString(), patterns);
  
  header.getURI().setQuery(qry);
  header.getURI().setPath(path);
  header.setHeader("X-Unique-Id", count);
  message.setRequestBody(new HttpRequestBody(body));

  count++;
}

/**
 * Processes the fuzz result.
 * Called after receiving the fuzzed message from the server
 * 
 * @param {HttpFuzzerTaskProcessorUtils} utils - A utility object that contains functions that ease common tasks.
 * @param {HttpFuzzResult} fuzzResult - The result of sending the fuzzed message.
 * @return {boolean} Whether the result should be accepted, or discarded and not shown.
 */
function processResult(utils, fuzzResult){
  return true;
}
