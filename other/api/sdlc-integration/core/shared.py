# This file contains functions that are used in both scan.py and zap_session.py

import logging
import sys
import time
from zapv2 import ZAPv2
import core.config as config

def init_zap():
	zap = ZAPv2(proxies={ 'http': config.zap_url, 'https': config.zap_url })

	# Wait for ZAP to start
	wait_timeout = 120 # 2min
	while(wait_timeout > 0):
		wait_timeout -= 1
		try:
			logging.debug ('ZAP Version ' + zap.core.version)
			break
		except IOError:
			logging.debug ('Waiting for ZAP to start...')
			time.sleep(1)

	if(wait_timeout <= 0):
		logging.debug ('Timed out. Quitting...')
		sys.exit()

	return zap


def write_config_file(filename, zap):
	all_passive_rules = zap.pscan.scanners
	all_ascan_rules = zap.ascan.scanners()
	all_dict = {}
	for rule in all_passive_rules:
		plugin_id = rule.get('id')
		all_dict[plugin_id] = { "name": rule.get('name'), "status": 'WARN' }

	for rule in all_ascan_rules:
		plugin_id = rule.get('id')
		all_dict[plugin_id] = { "name": rule.get('name'), "status": 'FAIL' }

	# Create the config file
	with open(filename, 'w') as f:
		f.write('# ZAP scan rule configuraion file\n')
		f.write('# change WARN to IGNORE to ignore rule or FAIL to fail if rule matches\n')
		f.write('# only the rule identifiers are used - the names are just for info\n')
		for key, rule in sorted(all_dict.iteritems()):
			f.write('{}\t{}\t({})\n'.format(key, rule["status"], rule["name"]))

		logging.info("Config file template has been saved - " + filename)


def read_config_file(filename):
	config_dict = {}
	# load config file
	with open(filename) as f:
		for line in f:
			if not line.startswith('#') and len(line) > 1:
				(key, val, ignore) = line.split('\t')
				config_dict[key] = val

	return config_dict

