Extender scripts
================

Scripts which can add new functionality, including graphical elements and new API end points.

## JavaScript template

```JavaScript
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall function when it is disabled.
// Any functionality added in the install function should be removed in the uninstall method.
// See the other templates for examples on how to do add different functionality. 

/**
 * This function is called when the script is enabled.
 * 
 * @param helper - a helper class which provides the methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *			It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 *	Links to any functionality added should be held in script variables so that they can be removed in uninstall.
 */
function install(helper) {
}

/**
 * This function is called when the script is disabled.
 * 
 * @param helper - a helper class which provides the methods:
 *		getView() this returns a View object which provides an easy way to add graphical elements.
 *			It will be null is ZAP is running in daemon mode.
 *		getApi() this returns an API object which provides an easy way to add new API calls.
 */
function uninstall(helper) {
}
```

## Parameters
| Name | JavaDoc |
| --- | --- |
| helper | ExtenderScriptHelper (no JavaDocs, see below for code link) |

## Code Links
* [ExtenderScript](https://github.com/zaproxy/zap-extensions/blob/master/addOns/scripts/src/main/java/org/zaproxy/zap/extension/scripts/ExtenderScript.java)
* [ExtenderScriptHelper](https://github.com/zaproxy/zap-extensions/blob/master/addOns/scripts/src/main/java/org/zaproxy/zap/extension/scripts/ExtenderScriptHelper.java)

## Templates in other languages

* Groovy : [ExtenderDefaultTemplate.groovy](https://github.com/zaproxy/zap-extensions/blob/master/addOns/groovy/src/main/zapHomeFiles/scripts/templates/extender/ExtenderDefaultTemplate.groovy)
* Jython : [Extender default template.py](https://github.com/zaproxy/zap-extensions/blob/master/addOns/jython/src/main/zapHomeFiles/scripts/templates/extender/Extender%20default%20template.py)
