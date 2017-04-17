"""

looks for parameter values that are reflected in the response.
Author: maradrianbelen.com

The scan function will be called for request/response made via ZAP, excluding some of the automated tools
Passive scan rules should not make any requests 

Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  
def compare(paramvalue_pair,msg): #get the value in a single parameter and compare it on the HTTP response.
	value=paramvalue_pair.split('=')
	#print 'parameter ' + value[0]+ ' is equal to ' + value[1]
	# add scan for header
	body=msg.getResponseBody().toString()
	header=msg.getResponseHeader().toString();
	reflected=''
	if body.find(value[1])>-1 or header.find(value[1])>-1:
		reflected=value[0]
	return reflected
	


def scan(ps, msg, src):
	reflected_params=''
	URI=msg.getRequestHeader().getURI();
	query=msg.getRequestHeader().getURI().getQuery();
	print 'params of ' + URI.toString();
	print '\n'
	#get a LIST of  param:value pairs. i.e test=ddd&ddd=sdsd
	if msg.getRequestHeader().getURI().getQuery():
		uriofreflected_param=msg.getRequestHeader().getURI().toString()
		paramvalue_pair=query.split('&');#test=ddd
		i=0;
		while(i<len(paramvalue_pair)): # send a single param:value pair.
			if(compare(paramvalue_pair[i],msg)):
				reflected_params=reflected_params + ',' + compare(paramvalue_pair[i],msg)
			i=i+1;
		if(reflected_params):
			ps.raiseAlert(0, 2, 'Find reflected parameter values', 'Reflected parameter value has been found. A reflected parameter values may introduce XSS vulnerability or HTTP header injection.',
			uriofreflected_param,
			'Reflected Parameters: ' + reflected_params, 'blank', 'blank', '', '', 0, 0, msg);
	else:
		print URI.toString() + ' has no parameter'

# line 36-40. the search code does not work properly, and it only shows the last reflected parameter if there is multiple reflected parameters in one HTTP REQUST
# I am wrong. the reflected_params parameter is incremented when a reflected parameter is found.