# ZAP Automated Security Test
This page demonstrates a project which shows how a dev team can run ZAP headless to run automated security tests and send the results to a bug-tracker (currently only JIRA).

ZAP is an Open Source Web App Security Testing Tool and browser proxy, that is very flexible and can be automated to run as part of a build.

## Project Setup

1.  Download and Install ZAP - [https://github.com/zaproxy/zaproxy/wiki/Downloads](https://github.com/zaproxy/zaproxy/wiki/Downloads)
2.  Add ZAP root certificate to your browser - Open ZAP > Tools > Options > Dynamic SSL Certificates > Save
3.  Start ZAP daemon (also see `demos/start-zap.sh` script): `zap.sh -daemon -port 8080 -config api.disablekey=true &`
4.  Configure your machine or browser to use ZAP local proxy for all internet traffic
5.  Download the project (https://github.com/zaproxy/community-scripts/archive/master.zip), unzip it and navigate into this directory (`/api/sdlc-integration`) - let's call it the root from now on.
6.  Install requirements: `pip install -r requirements.txt`
7.  Modify `core/config.py` - here you can configure:
    1. ZAP's URL
    2. Maximum duration of the active scan
    3. Your JIRA credentials and URL (the results of the scan can be posted to JIRA as a new issue). 
    4. For advanced active scanning you can also specify authentication for your web app, so that ZAP can log in and attack the app as a logged in user.
8.  Modify any `core/setup_module/proxy_scripts/*` as needed – all files in this folder will be used  (For instance you might want to add a CSP header to each response)
9.  Setup your own selenium drivers and tests (or any other way to generate internet traffic at a later stage).

## Structure

The project is split into two main modules - `setup_module` and `scan_module`. You should only care about the two scripts located in the root directory - `run_session_setup.py` and `run_scan.py`.

`run_session_setup.py` is used to clean the ZAP session and set up basic configuration - this should be run before any scans are run (+ it assumes that ZAP daemon is already running). 

After this point, you should generate some internet traffic going through the proxy. This could be done using your Selenium tests or via any other means. This could be as simple as running a few cURL commands (you can do additional spidering via the scripts later).

`run_scan.py` triggers the actual scan functions and can also post the scan results to JIRA - it assumes that ZAP daemon is running, session has been set up and selenium tests have been run (through the ZAP proxy)

## Usage

1.  *(optional)* Run `python run_session_setup.py -g rules_config.txt` to generate a template for your rule configuration file
2.  *(optional)* Change your `rules_config.txt` file to indicate which rules should be ignored and which should cause the test to fail
3.  To set up the session run: `python run_session_setup.py -t "www.example.com" -c rules_config.txt -d` where the `-d` (debug) and `-c filename` flags are optional. The `-t url` parameter is used to limit the proxy only to the target domain and avoid any other internet traffic from the machine. 
4.  Now you generate some internet traffic (targeting the domain you specified with the `-t` flag earlier). This is the point where you should run your Selenium tests.
5.  Run: `python run_scan.py -c rules_config.txt -r -d` to execute the test and have the results posted to JIRA (`-r` flag). Note that if you use the `-c filename` flag, you should use the same `rules_config.txt` file you used for the session setup!)
6.  *(optional)* If you want the `run_scan.py` script to perform additional spidering, specify a `-x filename` flag in the previous step, where the filename points to a file that contains a set of regexes (each on a new line) that limit the spider to particular subpaths of your site.
