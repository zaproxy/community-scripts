// Standalone script to demonstrate logging into OWASP Juice Shop (https://owasp.org/www-project-juice-shop/) 
// via Google SSO using Firefox.
// Juice Shop will need to be accessible via http://localhost:3000/ and you will need to change the 
// username and password to match a valid Google account.

var control
if (!control) control = Java.type("org.parosproxy.paros.control.Control").getSingleton()

var By = Java.type('org.openqa.selenium.By');
var Thread = Java.type('java.lang.Thread');
var juiceshop = 'http://localhost:3000/';
var username = 'zap.addo.sb@gmail.com'; // Change this to an account you own
var password = 'nottherealpassword';	// Change this to the right password for your account

var extSel = control.getExtensionLoader().getExtension(
				org.zaproxy.zap.extension.selenium.ExtensionSelenium.class) 

var wd = extSel.getWebDriverProxyingViaZAP(1, "firefox");
wd.get(juiceshop);
Thread.sleep(1000);
wd.get(juiceshop + '#/login');
Thread.sleep(1000);
wd.findElement(By.id("loginButtonGoogle")).click();
Thread.sleep(1000);
wd.findElement(By.id("identifierId")).sendKeys(username);
wd.findElement(By.className("RveJvd")).click();
Thread.sleep(1000);
wd.findElement(By.name("password")).sendKeys(password);
wd.findElement(By.className("RveJvd")).click();
