/*
This script will fill the OTP if MFA is configured on web-app. Browser-based auth is the pre-requisite for this script.
You need to analyze DOM of the web app this script needs to run on and modify the parameters accordingly.
This script assumes that the web app has fixed OTP for testing which can be stored in the variable below.
 */

function browserLaunched(utils) {
  var By = Java.type("org.openqa.selenium.By");
  var Thread = Java.type("java.lang.Thread");
  var url = utils.waitForURL(5000);
  var wd = utils.getWebDriver();
  var OTP = "123456";

  wd.get(url + "#/login");
  Thread.sleep(30000); //Wait for ZAP to handle the auth.
  wd.findElement(By.id("one-time-code")).sendKeys(OTP); //Replace the input field as per your web-app's DOM
  Thread.sleep(1000);
  wd.executeScript("document.querySelector('[aria-label=\"Verify Code\"]').click()"); //Replace the submit label as per your web-app's DOM
}
