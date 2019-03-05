// With many applications you, especially legacy, you want to
// treat the query params values are unique, since a query param
// indicate a unique page. Unfortunately, you may want to ignore
// some of the query params as unique, say if you have a session
// identifier in the url ... This takes the url, strips out the 
// extra query params you don't care about & checks if that has
// already been requested & drops if it has

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var Model      = Java.type('org.parosproxy.paros.model.Model');

// Query params for removal
// @todo make configureable?
var removeParams = {
  et:   /et=([0-9]{10})/,
  password: /password=([0-9a-z]{32})/,
  user: /user=([^\&]+)/,
}

// Strip out the query params we don't need
function stripUrlExtras(url) {
  for (var name in removeParams) {
    url = url.replace(removeParams[name],'').replace('&&', '&');
  }
  return url.replace(/\&+$/, "");
}

// Check if url matches HistoryReference
function urlMatchHistoryRef(url, historyRef) {
  // We only care about 200 status codes
  if (historyRef.getStatusCode() > 299) {
    return false;
  } 
  var test_url = historyRef.getURI().toString();
  test_url = stripUrlExtras(test_url);
  return (url === test_url);   
}

// Check if url is in SiteNode history
// http://www.zaproxy.org/2.5/javadocs/org/parosproxy/paros/model/SiteNode.html
function isUrlInHistory(url, node) {
  var history = node.getPastHistoryReference();
  var size = history.size();
  for (var z = 0; z < size; z++) {
    var item = history.get(z);
     if (urlMatchHistoryRef(url, item)) {
      return true;
    }
  }
  return false;
}


// Check if the url is somewhere in the tree of requests
// @todo optimize so we can skip some nodes based on their url unable to match
function isUrlInTree(url, node, level) {
  if (isUrlInHistory(url, node)) {
    return true;
  }
  
  var j;
  for (j =0; j < node.getChildCount(); j++) {
    var child = node.getChildAt(j);
    var found = isUrlInTree(url, child, level+1);

    if (found === true) {
      return true;
    }
  }
  return false;
}

// Set message to be dropped
function modifyToIgnore(msg)  {
  msg.setResponseBody("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n" +
  "<html><head></head><body><h1>403 Forbidden</h1>\n" +
  "Out of scope request blocked by ZAP script 'Drop requests not in scope.js'\n" +
  "</body></html>");
  msg.setResponseHeader("HTTP/1.1 403 Forbidden\r\n" +
  "Content-Type: text/html; charset=UTF-8\r\n" +
  "X-Zap-Spider-Ignore: 1");
  msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
}

// For intercepting/stopping requests before flight
function sendingRequest(msg, initiator, helper) {
  // If not spider ... continue on
  if (initiator !== HttpSender.SPIDER_INITIATOR) {return;}

  var headers  = msg.getRequestHeader();
  var url      = headers.getURI().toString();
  var rootNode = Model.getSingleton().getSession().getSiteTree().getRoot();  

  url = stripUrlExtras(url);
  
  var urlHasQuery = (url.indexOf('&') !== -1);

  // If sending url has no query params move on
  if (urlHasQuery) {return;}
  
  logger("Checking for url without params " + url)

  // If not in site tree ... move on
  if (!isUrlInTree(url, rootNode, 0)) {return;}

  logger('Already have made this request ... dropping')
  modifyToIgnore(msg);
  return;
}

function responseReceived(msg, initiator, helper) {}

