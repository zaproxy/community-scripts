# A template scan hook (https://www.zaproxy.org/docs/docker/scan-hooks/)
# Note that not all hooks will be called in all scans.

def cli_opts(opts):
	print("cli_opts({})".format(opts))

def zap_started(zap, target):
	print("zap_started({}, {})".format(zap, target))

def importing_openapi(target_url, target_file):
	print("importing_openapi({}, {})".format(target_url, target_file))

def importing_soap(target_url, target_file):
	print("importing_soap({}, {})".format(target_url, target_file))

def load_config(config, config_dict, config_msg, out_of_scope_dict):
	print("load_config({}, {}, {}, {})".format(config, config_dict, config_msg, out_of_scope_dict))

def print_rules_wrap(count, inprog_count):
	print("print_rules_wrap({}, {})".format(count, inprog_count))

def start_zap(port, extra_zap_params):
	print("start_zap({}, {})".format(port, extra_zap_params))

def start_docker_zap(docker_image, port, extra_zap_params, mount_dir):
	print("start_docker_zap({}, {}, {}, {})".format(docker_image, port, extra_zap_params, mount_dir))

def start_docker_zap_wrap(cid):
	print("start_docker_zap_wrap({})".format(cid))

def zap_access_target(zap, target):
	print("zap_access_target({}, {})".format(zap, target))

def zap_spider(zap, target):
	print("zap_spider({}, {})".format(zap, target))

def zap_spider_wrap(unused):
	print("zap_spider_wrap(unused)")

def zap_ajax_spider(zap, target, max_time):
	print("zap_ajax_spider({}, {}, {})".format(zap, target, max_time))

def zap_ajax_spider_wrap(unused):
	print("zap_ajax_spider_wrap(unused)")

def zap_active_scan(zap, target, policy):
	print("zap_active_scan({}, {}, {})".format(zap, target, policy))

def zap_active_scan_wrap(unused):
	print("zap_active_scan_wrap(unused)")

def zap_get_alerts(zap, baseurl, denylist, out_of_scope_dict):
	print("zap_get_alerts({}, {}, {}, {})".format(zap, baseurl, denylist, out_of_scope_dict))

def zap_get_alerts_wrap(alert_dict):
	print("zap_get_alerts_wrap({})".format(alert_dict))

def zap_import_context(zap, context_file):
	print("zap_import_context({}, {})".format(zap, context_file))

def zap_import_context_wrap(context_id):
	print("zap_import_context_wrap({})".format(context_id))

def zap_pre_shutdown(zap):
	print("zap_pre_shutdown({})".format(zap))

def pre_exit(fail_count, warn_count, pass_count):
	print("pre_exit({}, {}, {})".format(fail_count, warn_count, pass_count))

