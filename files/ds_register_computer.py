import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import json
import sys

# DEEP_SECURITY_ENDPOINT server and login credential
DEEP_SECURITY_ENDPOINT = ''

#"Accept":"text/plain", 
def register_computer(hostname):

#	url = DEEP_SECURITY_ENDPOINT + "/api/policies"
#	data = ""
#	post_header = {"Content-type": "application/json", 'api-secret-key': '4:+y5SkE7jAEG3Jt7hoeKsh34mBONgudoDrYyijLv2XXM=', "api-version": "v1"}
#	ret = requests.get(url, data=json.dumps(data), headers=post_header, verify=False)
#	print ret.status_code
#	print ret.content

	url = DEEP_SECURITY_ENDPOINT + "/api/computers"
	data = { "hostName": hostname, "displayName": hostname, "description": "GC", "groupID": 82 }
	post_header = {"Content-type": "application/json", 'api-secret-key': '4:+y5SkE7jAEG3Jt7hoeKsh34mBONgudoDrYyijLv2XXM=', "api-version": "v1"}
	ret = requests.post(url, data=json.dumps(data), headers=post_header, verify=False)
	print ret.status_code
	print ret.content

def main():

    if len(sys.argv) == 3:
        global DEEP_SECURITY_ENDPOINT
        DEEP_SECURITY_ENDPOINT = 'https://' + sys.argv[2] + ':4119'

        register_computer(sys.argv[1])
    else:
        print('target host name or ip required')
if __name__ == '__main__':
    main()