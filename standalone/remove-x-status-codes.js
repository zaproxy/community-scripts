// Remove 404s from request history
if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var ExtensionHistory = Java.type('org.parosproxy.paros.extension.history.ExtensionHistory');
var Control          = Java.type('org.parosproxy.paros.control.Control');
var Model            = Java.type('org.parosproxy.paros.model.Model');

var History  = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class)
var tree     = Model.getSingleton().getSession().getSiteTree()
var rootNode = tree.getRoot();	

function hasBadStatusCode(item) {
  if (item === null) {return true;}
  return item.getStatusCode() === 404 || item.getStatusCode() === 502;
}

function removeBadStatusCodeRef(item) {
	if (item === null || !hasBadStatusCode(item)) {
		return item;
	}
	logger('Delete ref ' + item)
	History.delete(item);
	return null;
}

// http://www.zaproxy.org/2.5/javadocs/org/parosproxy/paros/model/SiteNode.html
function crawlHistory(node) {
	var history = node.getPastHistoryReference();
	var size    = history.size();
	var lastRef = node.getHistoryReference();

	if (size === 0 && node.getChildCount() === 0 && hasBadStatusCode(lastRef)) {
		logger('Remove node ' + node)
		tree.removeNodeFromParent(node);
	} 

	lastRef = removeBadStatusCodeRef(lastRef);
 
	for (var i = 0; i < size; i++) {
		removeBadStatusCodeRef(history.get(i));
	}

	if (node.getPastHistoryReference().size() === 0 && lastRef === null && node.getParent() !== null) {
		logger('Remove node ' + node )
		tree.removeNodeFromParent(node);
	}
}

function crawlNode(node, level) {
  crawlHistory(node);
  for (var i = 0; i < node.getChildCount(); i++) {
	  var child = node.getChildAt(i);
    crawlNode(child, level+1);
  }
}

crawlNode(rootNode, 0);
