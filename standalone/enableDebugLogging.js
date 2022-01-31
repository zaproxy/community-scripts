var Configurator = Java.type("org.apache.logging.log4j.core.config.Configurator");
var Level = Java.type("org.apache.logging.log4j.Level");

// https://logging.apache.org/log4j/2.x/javadoc.html
Configurator.setLevel({
  // The following will enable DEBUG logging for the API
  "org.zaproxy.zap.extension.api.API" : Level.DEBUG,
  // The following will enable DEBUG logging for the Session Fixation scan rule
  "org.zaproxy.zap.extension.ascanrulesBeta.SessionFixationScanRule" : Level.DEBUG,
  // The following will enable DEBUG logging for the spider add-on
  "org.zaproxy.addon.spider" : Level.DEBUG,
});
