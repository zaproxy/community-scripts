//@zaproxy-standalone

/*
Note that the script below will work only on Zaproxy > 2.7.0
Since .getGlobalVars() is not supported on previous versions
*/

org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar('LIST', JSON.stringify(['Zaproxy', 'Zap', 'Simon', 'Mozilla']))

list = JSON.parse(org.zaproxy.zap.extension.script.ScriptVars.getGlobalVars()['LIST'])

list.forEach(function(item) {
	print(item)
})
