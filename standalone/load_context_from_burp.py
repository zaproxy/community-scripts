"""
This script will first prompt you to enter a name for the new context.
Then you will be prompted to choose a file, here you should choose
a burp project file (.json). The script will then create a new zap context
that matches the "scope" defined in the burp suite project.
"""
from javax.swing import JFrame
from javax.swing import JFileChooser
from javax.swing import JOptionPane
from org.parosproxy.paros.model import Model
import json


def get_context_name():
	ctx_name = JOptionPane.showInputDialog(None, "Enter a Name for the Context")
	return ctx_name


def get_file_name():
	frame = JFrame("Filename")
	frame.setLocation(100,100)
	frame.setSize(500,400)
	frame.setLayout(None)
	fc = JFileChooser()
	result = fc.showOpenDialog(frame)
	if not result == JFileChooser.APPROVE_OPTION:
		return None
	file_name = fc.getSelectedFile()
	return file_name


def get_url_regexes(file_name, include):
	with open(file_name, "r") as f:
		data = json.load(f)
	if include:
		includes = get_includes(data)
	else:
		includes = get_excludes(data)
	regexes = []
	for include in includes:
		host = get_host(include)
		protocol = get_protocol(include)
		if host.count(".") == 1:
			proper_regex = add_www_case(protocol, host)
			regexes.append(proper_regex)
		proper_regex = build_proper_regex(protocol, host)
		regexes.append(proper_regex)
	return regexes


def get_includes(data):
	return data['target']['scope']['include']


def get_excludes(data):
	return data['target']['scope']['exclude']


def add_www_case(protocol, host):
	host = "www." + host
	proper_regex = protocol + host + ".*"
	return proper_regex


def get_host(include):
	host = str(include['host'])
	host = host[1:-1]
	return host


def get_protocol(include):
	protocol = str(include['protocol'])
	if protocol == "http":
		protocol = "http:\/\/"
	else:
		protocol = "https:\/\/"
	return protocol


def build_proper_regex(protocol, host):
	proper_regex = protocol + host + ".*"
	return proper_regex


def create_new_context(ctx_name):
	session = Model().getSingleton().getSession()
	new_context = session.getNewContext(ctx_name)
	return new_context


def include_in_context(url_regexes, context):
	for pattern in url_regexes:
		context.addIncludeInContextRegex(pattern)


def exclude_from_context(url_regexes, context):
	for pattern in url_regexes:
		context.addExcludeFromContextRegex(pattern)


ctx_name = get_context_name()
file_name = get_file_name()
ctx = create_new_context(ctx_name)
include_url_regexes = get_url_regexes(str(file_name), True)
exclude_url_regexes = get_url_regexes(str(file_name), False)
include_in_context(include_url_regexes, ctx)
exclude_from_context(exclude_url_regexes, ctx)
