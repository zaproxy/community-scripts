// Example of how to use the Selenium webdriver to interact with a 
// dynamic page
if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

// Assumes Selenium extension is installed
// @todo add check to ensure Selenium is indeed installed
var Control           = Java.type('org.parosproxy.paros.control.Control')
var ExtensionSelenium = Java.type('org.zaproxy.zap.extension.selenium.ExtensionSelenium');
var HttpSender        = Java.type('org.parosproxy.paros.network.HttpSender');
var Thread            = Java.type('java.lang.Thread');
var Keys              = Java.type('org.openqa.selenium.Keys')
var Actions           = Java.type('org.openqa.selenium.interactions.Actions')
var By                = Java.type('org.openqa.selenium.By');
var WebElement        = Java.type('org.openqa.selenium.WebElement');
var WebDriver         = Java.type('org.openqa.selenium.WebDriver');

var selenium = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
var driver   = selenium.getWebDriverProxyingViaZAP(HttpSender.SPIDER_INITIATOR, 'firefox');

// Test against OWASP Juice Shop
driver.get('http://localhost:3000');
elements = driver.findElements(By.cssSelector("tr .btn-group a:first-child"));

for (var i in elements) {
   Thread.sleep(500);
   var el = elements[i];
   try {
     el.click()
     logger('click');
   } catch (e) {}
   Thread.sleep(300);

   var action = new Actions(driver);
   action.sendKeys(Keys.ESCAPE).perform();
   logger('esc');
}

Thread.sleep(2000);
driver.quit();
