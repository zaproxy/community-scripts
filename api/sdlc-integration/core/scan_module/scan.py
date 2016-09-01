# This script runs passive and active scans
# It depends on https://pypi.python.org/pypi/python-owasp-zap-v2 and requests
# It assumes that zap_session.py has been previously run and traffic been pushed
#
# It will exit with codes of:
#	0:	Success
#	1:	At least 1 FAIL
#	2:	At least one WARN and no FAILs
#	3:	Any other failure
# By default all alerts found by ZAP will be treated as WARNings.
# You can use the -c parameter to specify a configuration file to override this.
# You can generate a template configuration file using the -g parameter. You will
# then need to change 'WARN' to 'FAIL' or 'IGNORE' for the rules you want to be
# handled differently.

class StatusCode():
	success = 0
	fail = 1
	warn = 2
	other = 3

import getopt
import logging
import sys
import time
import requests
from datetime import datetime
from zapv2 import ZAPv2
import core.config as config
import core.shared as shared

logging.basicConfig(level=logging.INFO)

def usage():
		print ('Usage: scriptname.py [options]')
		print ('Options:')
		print ('    -c config_file    config file to use to IGNORE or FAIL warnings')
		print ('    -g gen_file       generate default config file (all rules set to WARN)')
		print ('    -r                HTML report will be generated and posted to JIRA')
		print ('    -x context_file   file with relevant URLs regexes for the spider - each on a new line')
		print ('                      e.g. only spider /account and /profile - (otherwise spider is turned off)')
		print ('    -d                show debug messages')
		print ('    -h                show this help and quit')


def create_jira_report(report, critical, details=""):
	# Write the report into a file
	filename = '/tmp/report.html'
	with open(filename, 'w') as f:
		# Save the report
		f.write (report)

	# Post a new issue to JIRA
	base_url = config.jira_base_url
	str_date = datetime.now().strftime('%Y-%m-%d %H:%M')
	descr = "ZAP security test produced the following HTML report."
	details = details.replace("\t", "    ")
	new_issue_data = {
		"fields": {
			"project": { "key": config.jira_project_key },
			"summary": "ZAP Security Report - " + str_date,
			"description": details + "\n\n" + descr,
			"issuetype": { "name": "Bug" },
			"priority": { "id": "2" if critical else "5"},
			"assignee": { "name": "" }
	   }
	}
	logging.debug(new_issue_data)
	auth = (config.jira_auth["user"], config.jira_auth["pw"])
	r = requests.post(base_url, json=new_issue_data, auth=auth)
	logging.debug(r.text)
	r = r.json()
	issue_key = r["id"]
	# Add the html report as an attachment
	r = requests.post(base_url + "/{}/attachments".format(issue_key), auth=auth,
		headers={"X-Atlassian-Token": "no-check"},
		files={'file': ('report.html', open(filename, 'rb'),  "text/html")})
	logging.debug(r.text)
	if( not critical ): # mark closed
		r = requests.post(base_url + "/{}/transitions".format(issue_key), auth=auth,
			json={ "transition": { "id": "2" } })
	logging.debug("Report complete")


def setup_zap_session_context(zap, ctx_targets):
	# Create a new context
	ctx_name = "testCtx"
	ctx_id = zap.context.new_context(ctx_name)
	if ctx_targets is None:
		# consider everything previously accessed
		zap.context.include_in_context(ctx_name, ".*")
	else:
		with open(ctx_targets) as f:
			for line in f:
				line = line.strip()
				if(len(line) > 1):
					zap.context.include_in_context(ctx_name, line)

	# Authentication
	login_url = config.target_auth["login_url"]
	zap.authentication.set_authentication_method(ctx_id, "formBasedAuthentication",
		"loginUrl="+ login_url + "&loginRequestData=email={%25username%25}%26password={%25password%25}")
	zap.authentication.set_logged_in_indicator(ctx_id, "signout") # any regexp
	zap.authentication.set_logged_out_indicator(ctx_id, "signup")

	return (ctx_id, ctx_name)


def setup_new_user(zap, ctx_id):
	user_id = zap.users.new_user(ctx_id, "test_user")
	zap.users.set_authentication_credentials(ctx_id, user_id,
		"password={}&username={}&type=UsernamePasswordAuthenticationCredentials"
		.format(config.target_auth["pw"], config.target_auth["user"]))
	zap.users.set_user_enabled(ctx_id, user_id, True)
	return user_id


def spider(zap, max_duration, ctx_id=None, ctx_name=None, user_id=None):
	# Spider target
	logging.debug ('Spider starting...')
	zap.spider.set_option_max_duration(max_duration) # Experimental
	# Start spidering based on the context rules (root URLs must have been accessed before)
	# spider_scan_id = zap.spider.scan(contextname=ctx_name, recurse=True, subtreeonly=True)
	spider_scan_id = zap.spider.scan_as_user(ctx_id, user_id, recurse=True, subtreeonly=True)
	logging.debug("Spider id: " + str(spider_scan_id))
	try:
		spider_scan_id = int(spider_scan_id)
	except:
		logging.debug("No URLs in context for spider to scan")
		return

	time.sleep(5)

	start = datetime.now()
	while (int(zap.spider.status(spider_scan_id)) < 100):
		if (datetime.now() - start).seconds > ((max_duration * 60) + 10): # Force max_duration
			logging.debug("Spider timeout exceeded - stopping...")
			zap.spider.stop(spider_scan_id)
			break
		if (zap.pscan.records_to_scan > 4000): # Otherwise the passive scan will take too long
			logging.debug("Records-to-scan number limit reached - stopping...")
			zap.spider.stop(spider_scan_id)
			break
		logging.debug ('Spider progress %: ' + zap.spider.status(spider_scan_id))
		time.sleep(5)
	logging.debug ('Spider complete')
	logging.debug(zap.spider.results(spider_scan_id))
	# logging.debug(zap.spider.full_results(spider_scan_id))


def passive_scan(zap):
	# Passive scans start right automatically after spidering (or accessing URLs)
	# Wait for the passive scanning to complete
	while (int(zap.pscan.records_to_scan) > 0):
		logging.debug ('Records to passive scan : ' + zap.pscan.records_to_scan)
		time.sleep(2)
	logging.debug ('Passive scanning complete')


def active_scan_single(zap, target, max_duration, ctx_id=None, user_id=None):
	# Unlike passive scan, active scan has to be manually triggered
	logging.debug("Active scan for " + target)
	active_scan_id = zap.ascan.scan(target, recurse=True, inscopeonly=True)
	# The following doesn't work - Pending Simon's explanation of the 'target' requirement
	# active_scan_id = zap.ascan.scan_as_user(target, ctx_id, user_id, recurse=True)
	try:
		active_scan_id = int(active_scan_id)
	except:
		logging.debug("No URLs in context for this target")
		return

	time.sleep(5)

	start = datetime.now()
	while (int(zap.ascan.status(active_scan_id)) < 100):
		if (datetime.now() - start).seconds > ((max_duration * 60) + 10): # Force max_duration
			logging.debug("Active scan timeout exceeded - stopping...")
			zap.ascan.stop(active_scan_id)
			break
		logging.debug ('Active scan progress %: ' + zap.ascan.status(active_scan_id))
		time.sleep(5)
	logging.debug ('Active scan for ' + target + ' complete')


def active_scan_all(zap, max_duration, ctx_id=None, user_id=None):
	sites = zap.core.sites
	total_sites = len(sites)
	t_num = 0
	for target in sites:
		active_scan_single(zap, target, max_duration, ctx_id, user_id)
		t_num += 1
		logging.debug("{}/{} active scans completed".format(t_num, total_sites))


def report_results(zap, config_dict):
	pass_count = 0
	warn_count = 0
	fail_count = 0
	ignore_count = 0
	report_string = 'Total of {} URLs\n'.format(len(zap.core.urls))

	# Retrieve the alerts
	alert_dict = {}
	alerts = zap.core.alerts()
	for alert in alerts:
		plugin_id = alert.get('pluginId')
		if (not alert_dict.has_key(plugin_id)):
			alert_dict[plugin_id] = []
		alert_dict[plugin_id].append(alert)

	all_rules = zap.pscan.scanners # AScan rules not considered PASS by default
	# print out the passing rules
	pass_dict = {}
	for rule in all_rules:
		plugin_id = rule.get('id')
		if (not alert_dict.has_key(plugin_id)):
			pass_dict[plugin_id] = rule.get('name')

	for key, rule in sorted(pass_dict.iteritems()):
		report_string += 'PASS: ' + rule + ' [' + key + ']\n'

	pass_count = len(pass_dict)

	# print out the failing rules
	for key, alert_list in sorted(alert_dict.iteritems()):
		if config_dict.has_key(key) and config_dict[key] == 'IGNORE':
			action = 'IGNORE'
			ignore_count += 1
		elif config_dict.has_key(key) and config_dict[key] == 'FAIL':
			action = 'FAIL'
			fail_count += 1
		else:
			action = 'WARN'
			warn_count += 1

		report_string += (action + ': {} [{}] x ' + str(len(alert_list))
			+ '\n').format(alert_list[0].get('alert'), alert_list[0].get('pluginId'))

		# Show (up to) first 5 urls
		for alert in alert_list[0:5]:
			report_string += ('\t' + alert.get('url') + '\n')

	report_string += ('\nFAIL: ' + str(fail_count) + '\tWARN: ' + str(warn_count)
		+ '\tIGNORE: ' + str(ignore_count) + '\tPASS: ' + str(pass_count) + '\n')

	print (report_string)

	if fail_count > 0:
		ret_code = StatusCode.fail
	elif warn_count > 0:
		ret_code = StatusCode.warn
	elif pass_count > 0:
		ret_code = StatusCode.success
	else:
		ret_code = StatusCode.other

	return (ret_code, report_string)


def main(argv):
	config_read = None
	config_write = None
	report_jira = False
	ctx_targets = None

	try:
		opts, args = getopt.getopt(argv,"x:c:g:rdh")
	except getopt.GetoptError:
		usage()
		sys.exit(StatusCode.other)

	for opt, arg in opts:
		if opt == '-x':
			ctx_targets = arg
		elif opt == '-c':
			config_read = arg
		elif opt == '-g':
			config_write = arg
		elif opt == '-d':
			logging.getLogger().setLevel(logging.DEBUG)
		elif opt == '-r':
			report_jira = True
		elif opt == '-h':
			usage()
			sys.exit(StatusCode.success)

	# Init
	zap = shared.init_zap()

	# Only want to generate the config template?
	if config_write is not None:
		shared.write_config_file(config_write, zap)
		sys.exit(StatusCode.success)

	# Read user-defined rules for tagging scan results
	config_dict = shared.read_config_file(config_read) if config_read is not None else {}

	# >>>>>>>>>> DEBUG:
	# zap.urlopen("http://example.com")
	# zap.core.access_url(target, True) <- doesn't use zap proxy ?
	# <<<<<<<<<< END DEBUG

	# Scanning contexts, + auth setup
	ctx_id, ctx_name = setup_zap_session_context(zap, ctx_targets)
	user_id = setup_new_user(zap, ctx_id)

	# Spider - Crawl links on webpages that we've accessed before
	# Although, our original proxy traffic might be sufficient
	if(ctx_targets is not None):
		spider(zap, config.max_duration, ctx_id, ctx_name, user_id)

	# Passive scan (wait to finish)
	passive_scan(zap)

	# Active scan all domains
	active_scan_all(zap, config.max_duration, ctx_id, user_id)

	if (len(zap.core.urls) == 0):
		logging.warning('No URLs found - is the target accessible?')
	else:
		status_code, report_string = report_results(zap, config_dict)
		if(report_jira):
			create_jira_report(zap.core.htmlreport(), status_code == StatusCode.fail, report_string)
		sys.exit(status_code)

	sys.exit(StatusCode.other)

