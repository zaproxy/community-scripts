// Boilerplate for sequence script

if (typeof println == 'undefined') this.println = print;

var List = Java.type('java.util.List');
var View = Java.type('org.parosproxy.paros.view.View');

// Logging with the script name is super helpful!
function logger() {
  print('[' + this['zap.script.name'] + '] ' + arguments[0])
  View.getSingleton().getOutputPanel().appendAsync('[' + this['zap.script.name'] + '] ' + arguments[0] + "\n")
}

function runSequenceBefore(msg, plugin) {
  logger('run-before');
}

function runSequenceAfter(msg, plugin) {
  logger('after-after');
}

function isPartOfSequence(msg) {
  logger('is-part-of');
  return true;
}

function getAllRequestsInScript() {
  return new List();
}

function scanSequence() {
  logger('Start');
}