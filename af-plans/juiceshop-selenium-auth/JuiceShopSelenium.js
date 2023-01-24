/*
This is part of a set of scripts which allow you to authenticate to Juice Shop using Selenium.

These scripts will currently only run in Oracle Nashorn and not Graal.js 
which means you need to run ZAP using Java 11.

---

This script logs in to Juice Shop when a browser is launched.
This will happen when:
* The authentication script runs
* The AJAX Spider launches a browser
* The DOM XSS scan rule runs

This is needed as Juice Shop maintains client side state about authentication -
if the UI does not know it is authenticated then it will not be able to
perform any authenticated actions.

*/

function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

var ArrayList = Java.type("java.util.ArrayList");
var By = Java.type('org.openqa.selenium.By');
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var System = Java.type("java.lang.System");

var juiceshopAddr = "http://localhost:3000/";

function browserLaunched(utils) {
	var wd = utils.getWebDriver();
	wd.get(juiceshopAddr);
	// This request will get the login page without the pesky popup
	wd.get(juiceshopAddr + "#/login");
	// These are standard selenium methods for filling out fields
	// You will need to change them to support different apps
	wd.findElement(By.id("email")).sendKeys(System.getenv("JS_USER"));
	wd.findElement(By.id("password")).sendKeys(System.getenv("JS_PWD"));
	wd.findElement(By.id("loginButton")).click();
}

