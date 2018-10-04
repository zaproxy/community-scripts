// Set scripts vars, designed to be chained with ZEST scripts.
// For example you may have a ZEST script that get's a JWT token
// and another httpsender that uses rewrites the header to add that token
// ... you can pass that token between with this script
if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
  var View = Java.type('org.parosproxy.paros.view.View');
  var message = '[' + (this['zap.script.name'] || 'set-vars') + '] ' + arguments[0];
  println(message);
  View.getSingleton().getOutputPanel().appendAsync(message + "\n");
}

function main() {
  var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
  var attrs = Object.keys(this).filter(function(k) { 
    return ['zap.script.name','logger','println', 'main'].indexOf(k) === -1;
  });

  for (var i in attrs) {
    var attr = attrs[i];
    logger("Setting script var " + attr + " = " + this[attr]);
    ScriptVars.setGlobalVar(attr, this[attr]);
  }
}

main();
