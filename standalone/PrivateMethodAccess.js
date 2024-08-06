/*
When writing scripts you may find that you need to access private java methods.
This script shows how you can do this easily.

WARNING: we do not consider private methods to be part of the public API, so they may
be changed or removed at any time.
If you think you have a strong case for making a method public then either:

1. Ask on the ZAP Dev Group: https://groups.google.com/group/zaproxy-develop
2. Submit a pull request making the change (but be prepared for it to be rejected)

*/

var ExtensionAlert = Java.type(
  "org.zaproxy.zap.extension.alert.ExtensionAlert"
);
var MethodUtils = Java.type("org.apache.commons.lang3.reflect.MethodUtils");

extAlert = control.getExtensionLoader().getExtension(ExtensionAlert);

print(extAlert);

// Note that there are a lot of other methods in MethodUtils if these are not what you are looking for.

// Call a private method with no parameters
print(MethodUtils.invokeMethod(extAlert, true, "getAlertPanel"));

// Call a private method with parameters
print(MethodUtils.invokeMethod(extAlert, true, "applyOverride", "abc", "+def"));
