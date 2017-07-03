# This script should be run to clean and set up ZAP session and is independent of scan.py

class StatusCode():
	success = 0
	fail = 1
	warn = 2
	other = 3

import os
import getopt
import logging
import sys
import urlparse
from zapv2 import ZAPv2
import core.shared as shared

logging.basicConfig(level=logging.INFO)

def usage():
		print ('Usage: scriptname.py -t <target_url> [options]')
		print ('    -t target_url     base url to include (everything else will be excluded from the proxy traffic)')
		print ('                      e.g. www.example.com (http + https are both included)')
		print ('Options:')
		print ('    -c config_file    config file to use to IGNORE or FAIL warnings')
		print ('    -g gen_file       generate default config file (all rules set to WARN)')
		print ('    -d                show debug messages')
		print ('    -h                show this help and quit')


def normalize_input_url(target):
	if(target is None or len(target) < 2):
		usage()
		sys.exit(StatusCode.other)

	if(target.find("//") == -1):
		target = "//" + target

	base_url = urlparse.urlparse(target).netloc
	logging.debug("Base url: " + base_url)
	return base_url


def add_proxy_scripts(zap):
	script_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "proxy_scripts")
	for script in os.listdir(script_dir):
		filename = os.path.join(script_dir, script)
		# Note: scriptDescription parameter is required - API bug
		zap.script.load(script, "proxy", "ECMAScript : Oracle Nashorn", filename, "")
		response = zap.script.enable(script)
		logging.debug("Loaded: " + filename + " - " + response)


def clean_zap_session(zap, target_url, config_dict):
	# Throw away any previous state
	zap.core.new_session()
	add_proxy_scripts(zap)

	# Passive scan runs automatically for all accessed site no matter the context
	# Exclude url regexes here - e.g. exclude everything but the target
	zap.core.exclude_from_proxy("^(?:(?!https?:\/\/" + target_url + ").*).$")

	# Scanner settings
	# There are multiple passive scanners scanning for different vulnerabilities
	# They can be listed 'print(zap.pscan.scanners)' and disabled by their ID here
	zap.pscan.enable_all_scanners()
	zap.ascan.enable_all_scanners()
	ignored_scanners = ",".join([ i for i in config_dict if config_dict[i] == "IGNORE" ])
	if ignored_scanners:
		logging.info("Ignored scanners: " + ignored_scanners)
		zap.pscan.disable_scanners(ignored_scanners) # ids*
		zap.ascan.disable_scanners(ignored_scanners) # ids*
	# ERR: disabling scanners not affecting scan time, only excluding from final result???

	# Set ascan strength - LOW, MEDIUM, HIGH
	policies = zap.ascan.policies()
	for policy in policies:
		pid = policy['id']
		zap.ascan.set_policy_attack_strength(pid, 'LOW')


def main(argv):
	config_read = None
	config_write = None
	target_url = None

	try:
		opts, args = getopt.getopt(argv,"t:c:g:dh")
	except getopt.GetoptError:
		usage()
		sys.exit(StatusCode.other)

	for opt, arg in opts:
		if opt == '-t':
			target_url = arg
		elif opt == '-c':
			config_read = arg
		elif opt == '-g':
			config_write = arg
		elif opt == '-d':
			logging.getLogger().setLevel(logging.DEBUG)
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

	# Setup session context + auth
	target_url = normalize_input_url(target_url)
	clean_zap_session(zap, target_url, config_dict)

