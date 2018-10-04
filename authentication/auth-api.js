// Generic authentication script for authing against an API
if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader        = Java.type('org.parosproxy.paros.network.HttpHeader');
var URI               = Java.type('org.apache.commons.httpclient.URI');

function authenticate(helper, paramsValues, credentials) {
  var token, msg, resbody = '';
  var loginApiUrl = paramsValues.get('API URL');
  var jsonString  = paramsValues.get('JSON'); // '{"email":"%username%","password":"%password%"}'
  var username = credentials.getParam('Username');
  var password = credentials.getParam('Password');

 
  var reqbody = jsonString.replace('%username%', username).replace('%password%', password);
  var requri    = new URI(loginApiUrl, false);
  var reqheader = new HttpRequestHeader(HttpRequestHeader.POST, requri, HttpHeader.HTTP10);

  reqheader.setHeader('Content-Type', 'application/json;charset=UTF-8')
  msg = helper.prepareMessage();
  msg.setRequestHeader(reqheader);
  msg.setRequestBody(reqbody);

  logger(' Sending POST to ' + requri + ' with body: ' + reqbody);

  helper.sendAndReceive(msg);
  resbody = msg.getResponseBody().toString();
  
  try {
    var data = JSON.parse(resbody);
    token = data["authentication"]["token"]
    org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar("target-api.token", token)
  } catch (e) {
    logger('cant-parse-json - auth failed?')
    logger(resbody)
  }
  return msg;
}


function getRequiredParamsNames() {
  return ['API URL', 'JSON'];
};

function getOptionalParamsNames() {
  return ['TokenAttr'];
};

function getCredentialsParamsNames() {
  return ['Username', 'Password'];
};
