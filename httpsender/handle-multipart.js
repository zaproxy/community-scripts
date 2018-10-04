// ZAP currently does not handle multi-part forms, so this
// stands in the gap and parses multi-part requests and 
// adds the params to the Params store
if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var Control         = Java.type('org.parosproxy.paros.control.Control');
var ExtensionParams = Java.type('org.zaproxy.zap.extension.params.ExtensionParams');
var SiteParameters  = Java.type('org.zaproxy.zap.extension.params.SiteParameters');
var HtmlParameter   = Java.type('org.parosproxy.paros.network.HtmlParameter');

var rexname = /name=["']([^'"]+)["']/;

// Capture post requests with multipart forms
function sendingRequest(msg, initiator, helper) {
  var headers = msg.getRequestHeader();

  // If it's not a post request, notthing to do
  if (headers.getMethod() !== 'POST') {return;}
  
  var contentType = headers.getHeader('Content-Type');
  var isMultipart = contentType.indexOf('boundary=') !== -1;
  
  // If the request is not multipart, return
  if (!isMultipart) {return;}

  var boundary  = contentType.split('boundary=').pop();
  var reqbody   = msg.getRequestBody().toString();
  var site      = msg.getRequestHeader().getHostName() + ":" + msg.getRequestHeader().getHostPort();
  var extension = Control.getSingleton().getExtensionLoader().getExtension(ExtensionParams.class)
  var params    = extension.getSiteParameters(site);
  
  if (!params) {
    params = new SiteParameters(extension, site);
  }

  var data = reqbody.split(boundary);
  
  for (var i in data) {
    var lines = data[i].split("\n");
    if (!lines[1]) {continue;}
    
    // Extra empty line
    lines.shift();
    var name = rexname.exec(lines.shift());
    if (!name[1]) {continue};
    name = name[1];
    logger(i + " " + name)
    
    // First & last lines are extras
    lines.shift();
    lines.pop();
  
    var value = lines.join("\n");
    var param = new  HtmlParameter(HtmlParameter.Type.form, name, value);
    params.addParam(site, param, msg);

    logger("Added a multipart param by name of " + name);
  }

  return false;
}

function responseReceived(msg, initiator, helper) {}
