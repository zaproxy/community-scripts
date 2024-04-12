// Standalone script to demonstrate logging into OWASP Juice Shop (https://owasp.org/www-project-juice-shop/)
// via the standard login form using Firefox.
// Juice Shop will need to be accessible via http://localhost:3000/ and you will need to register
// a user with a name of test@test.com and a password of test123
// You can change any of the variables to match your environment if needed.

var By = Java.type("org.openqa.selenium.By");
var Thread = Java.type("java.lang.Thread");
var juiceshop = "http://localhost:3000/";
var username = "test@test.com";
var password = "test123";

var extSel = control
  .getExtensionLoader()
  .getExtension(org.zaproxy.zap.extension.selenium.ExtensionSelenium.class);

var wd = extSel.getWebDriverProxyingViaZAP(1, "firefox");
wd.get(juiceshop);
Thread.sleep(1000);
wd.get(juiceshop + "#/login");
wd.findElement(By.id("email")).sendKeys(username);
wd.findElement(By.id("password")).sendKeys(password);
wd.findElement(By.id("loginButton")).click();
