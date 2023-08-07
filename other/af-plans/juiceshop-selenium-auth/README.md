# Juice Shop Selenium Authentication

This directory contains [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) YAML plans and a set of scripts to demonstrate how to set up ZAP to automate authentication using Selenium to launch browsers.

Note that ZAP _can_ authenticate to Juice Shop _without_ using Selenium, and normally this is what we would recommend.
However, in this case we are using it to show how to use Selenium to authenticate to your app if there is no alternative.

There is a related blog post: https://www.zaproxy.org/blog/2023-02-01-authenticating-using-selenium/

## Requirements

To run this plan you need to:

* Install Java 11 - unfortunately we currently have to use Oracle Nashorn for the Selenium scripting which is not available in later versions of Java
* Install ZAP
* Run [Juice Shop](https://github.com/juice-shop/juice-shop) so that it is accessible via http://localhost:3000/
* Add a user to Juice Shop with the credentials:
  * username: test@test.com
  * password: test123
* Edit all of the shell scripts to correct the path to your ZAP installation and to the plans
* Ensure that the user credentials are available via the environmental variables (these _should_ be set up correctly via the supplied scripts):
  * JS_USER: test@test.com
  * JS_PWD: test123

## Test Run

With the above requirements in place run the script `./js-test.js` (Linux or macOS) or `js-test.bat` (Windows).

This uses the `juiceshop-test-req.yaml` file which sets up the environment and just makes one authenticated request.

A set of [Job Tests](https://www.zaproxy.org/docs/desktop/addons/automation-framework/tests/) check that the authentication worked as expected.

You should see messages on standard output like:

```
Job requestor test of type stats passed: At least 1 successful login [1 >= 1]
Job requestor test of type stats passed: No login failures [0 <= 0]
Job requestor finished
Automation plan succeeded!
```

These indicate that the plan ran successfully.

Note that Firefox reports lots of messages to standard output - these are difficult to suppress :/

To show that ZAP fails the plan if the authentication fails, either do not register the user or change the script to use different credentials.

## Full Run

With the above requirements in place run the script `./js-auth.js` (Linux or macOS) or `js-auth.bat` (Windows).

This uses the `juiceshop-auth.yaml` file which sets up the environment and runs both the standard and AJAX Spider,
both of which authenticate using the `test@test.com` user.

A set of [Job Tests](https://www.zaproxy.org/docs/desktop/addons/automation-framework/tests/) check that the authentication worked as expected for both spiders.

You should see messages on standard output like:

```
Job spiderAjax found 1,898 URLs
Job spiderAjax test of type stats passed: At least 1000 URLs found [1898 >= 1000]
Job spiderAjax test of type stats passed: At least 1 successful login [1 >= 1]
Job spiderAjax test of type stats passed: No login failures [0 <= 0]
Job spiderAjax test of type stats passed: At least 300 authentication tokens present [374 >= 300]
Job spiderAjax test of type stats failed: Less than 500 authentication tokens absent [1051 >= 500]
Job spiderAjax test of type stats passed: At least 300 authentication cookies present [930 >= 500]
Job spiderAjax test of type stats passed: Less than 500 authentication cookies absent [495 < 500]
Job spiderAjax finished
Job passiveScan-wait started
Job passiveScan-wait finished
Automation plan succeeded!
```

These indicate that the plan ran successfully.

Note that Firefox reports lots of messages to standard output - these are difficult to suppress :/

## Plans

The following related enhancements are planned:

* Add example docker commands
* Update the plan to use header based session management
* More investigations into why there are so many auth tokens and cookies absent in browser requests

