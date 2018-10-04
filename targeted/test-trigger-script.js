if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
  print(this['zap.script.name'] + ']' +  arguments[0]);
}

// Example script that you can trigger in the UI 
// when you right click a request item and click Invoke
function invokeWith(msg) {
  logger(msg.getHistoryRef());
}
