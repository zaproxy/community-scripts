if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var ExtensionHistory = Java.type('org.parosproxy.paros.extension.history.ExtensionHistory');
var Control          = Java.type('org.parosproxy.paros.control.Control');
var Model            = Java.type('org.parosproxy.paros.model.Model');

var History = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class)

function sendingRequest(msg, initiator, helper) {}

function responseReceived(msg, initiator, helper) {
	var historyRef = msg.getHistoryRef();
	var msgid = History.getLastHistoryId() + 1;

	if (historyRef !== null) {
		msgid = historyRef.getHistoryId();
	}
	
	var header  = msg.getResponseHeader();
	header.addHeader('X-Zap-Msgid', '' + msgid);
	msg.setResponseHeader(header);
}
