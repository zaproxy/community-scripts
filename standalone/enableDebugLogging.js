var Level = Java.type("org.apache.logging.log4j.Level")
var LoggerContext = Java.type("org.apache.logging.log4j.core.LoggerContext")

var context = LoggerContext.getContext()
var config = context.getConfiguration()

// The following will enable DEBUG logging for the API
// config.getLoggerConfig("org.zaproxy.zap.extension.api.API").setLevel(Level.DEBUG)
// The following will enable DEBUG logging for the SessionFixation scanner
config.getLoggerConfig("org.zaproxy.zap.extension.ascanrulesBeta.SessionFixation").setLevel(Level.DEBUG)

context.updateLoggers()