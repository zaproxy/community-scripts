# This scan hook (https://www.zaproxy.org/docs/docker/scan-hooks/)
# copies the ZAP session and log file into a directory mounted to /zap/wrk after ZAP has shut down.
# There must not be a local 'session' directory otherwise the script will fail.

from shutil import copy2, copytree
import os.path

# This assumes that you are running as zap - if you run as root change to use /root/.ZAP(_D)
dev_path = '/home/zap/.ZAP_D'
rel_path = '/home/zap/.ZAP'

def pre_exit(fail_count, warn_count, pass_count):
	dir = rel_path
	if os.path.exists(dev_path + '/session'):
		dir = dev_path
	copytree(dir + '/session', '/zap/wrk/session')
	copy2(dir + '/zap.log', '/zap/wrk')
