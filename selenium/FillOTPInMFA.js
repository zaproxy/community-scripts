// This script can be used to fill in the OTP if it appears right after the authentication.
// This can only work for the apps who have fixed OTP in MFA

function browserLaunched(utils) {
  var By = Java.type("org.openqa.selenium.By");
  var Thread = Java.type("java.lang.Thread");
  var url = utils.waitForURL(5000);
  var wd = utils.getWebDriver();
  var OTP = "123456";

  wd.get(url + "#/login");
  Thread.sleep(30000); //Wait for ZAP to handle the auth.
  wd.findElement(By.id("one-time-code")).sendKeys(OTP);
  wd.executeScript(
    "document.querySelector('flt-glass-pane').shadowRoot.querySelector('flt-semantics-placeholder').click({force: true})"
  ); //Used with Flutter apps only
  Thread.sleep(1000);
  wd.executeScript(
    "document.querySelector('[aria-label=\"Verify Code\"]').click()"
  );
}
