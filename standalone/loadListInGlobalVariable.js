//@zaproxy-standalone

org.zaproxy.zap.extension.script.ScriptVars.setGlobalVar('LIST', JSON.stringify(['Zaproxy', 'Zap', 'Simon', 'Mozilla']))

list = JSON.parse(org.zaproxy.zap.extension.script.ScriptVars.getGlobalVars()['LIST'])

list.forEach(function(item) {
	print(item)
})