if (typeof println == 'undefined') this.println = print;

// Logging with the script name is super helpful!
function logger() {
	print('[' + this['zap.script.name'] + '] ' + arguments[0]);
}

function map(list, callback) {
	var items = [];
	for (var i in list) {
		var d;
		try {
			d = callback(list[i]);
		} catch (e) {}
		items.push(d)
	}
	return items;
}

// Assumes Selenium extensions is installed
var Control           = Java.type('org.parosproxy.paros.control.Control')
var ExtensionSelenium = Java.type('org.zaproxy.zap.extension.selenium.ExtensionSelenium');
var HttpSender        = Java.type('org.parosproxy.paros.network.HttpSender');
var Thread            = Java.type('java.lang.Thread');
var Keys              = Java.type('org.openqa.selenium.Keys')
var Actions           = Java.type('org.openqa.selenium.interactions.Actions')
var By                = Java.type('org.openqa.selenium.By');
var WebElement        = Java.type('org.openqa.selenium.WebElement');
var WebDriver         = Java.type('org.openqa.selenium.WebDriver');


function getLinks(driver) {
	var elements = driver.findElements(By.cssSelector("a[href^='#']"));
	return map(elements, function(el)  {
		return el.getAttribute('href');
	});
}

function clickNthSelector(driver, num, selector) {
  var elements = driver.findElements(By.cssSelector(selector));
  clickElement(elements[num]);
}

function clickElement(el) {
  if (!el) {
    logger('Nothing to click')
    return false;
  }
   
  try {
    if (!el.isDisplayed()) {
      logger('Not visible')
      return false;
    }
  } catch (e) {
    return false;
  }
  
  try {
    el.click()
    logger('click')
  } catch (e) {}

  Thread.sleep(300);
  var action = new Actions(driver);
  action.sendKeys(Keys.ESCAPE).perform();
  logger('esc');
  Thread.sleep(200);
}


function clickButtons(driver) {
  var currentUrl = driver.getCurrentUrl();
  var selector = "[ng-click]";

  Thread.sleep(600);

  var elements = driver.findElements(By.cssSelector(selector));
  var skip = elements.length;

  logger("Found " + skip)

  for (var i = 0; i < skip; i++) {
    logger('Sarting click ' + i)
    try {
      clickNthSelector(driver, i, selector);
    } catch (e) {
      break;
    }
    
    if (driver.getCurrentUrl() !== currentUrl) {
      driver.get(currentUrl);
      Thread.sleep(200);
    }
  }
}

var selenium = Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
var driver = selenium.getWebDriver(HttpSender.SPIDER_INITIATOR, 'firefox');

driver.get('http://localhost:3000');

var links = getLinks(driver);

for (var i in links) {
	logger('Navigating to ' + links[i]);
	driver.get(links[i]);
	clickButtons(driver);
}

Thread.sleep(2000);
driver.quit();
