#!/usr/bin/python
ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ds

short_description: Create or terminate Deep Security Computers

version_added: "2.6"

description:
    - "This module creates or deletes computer objects within Deep Security.
       The computer does not necesarily be protected by Deep Security"

options:
    hostname:
        description:
            - The hostname to handle
        required: true
    state:
        description:
            - The desired state. Choices present or absent
        required: true
    group_id:
        description:
            - The desired group for the computer object
        required: false
    dsm_url:
        description:
            - The Deep Security Manager URL to query
        required: true
    api_key:
        description:
            - The API Key to access the Deep Security REST APPI

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
'''

EXAMPLES = '''
# Retriece covered CVEs and rules covering
- name: Deletes computer within Deep Security
  ds:
    hostname: "terminated.example.com"
    state: absent
    dsm_url: "https://{{ deepsecurity_manager }}:4119"
    api_key: "{{ deepsecurity_api_key }}"

- name: Ensures that computer exists within Deep Security
  ds:
    hostname: "dockerhost.example.com"
    state: present
    group_id: 87
    dsm_url: "https://{{ deepsecurity_manager }}:4119"
    api_key: "{{ deepsecurity_api_key }}"

'''

RETURN = '''
ds_protection_status:

UPDATE!!!

    description: The current protection status realized with the HIPS module
    type: dict
    sample:
        "changed": true,
        "failed": false,
        "json": {
            "cves_covered": [
                "CVE-2015-1716",
                "CVE-2015-4000",
                "CVE-2016-8858"
            ],
            "rules_covering": [
                3712,
                5555
            ]
        },
        "message": ""
'''

from ansible.module_utils.basic import AnsibleModule
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import requests
import json
import sys

def search_computer(hostname, dsm_url, api_key):
    '''
    Searches for computer and returns ID if present.
    Returns -1 is absent
    '''

    url = dsm_url + "/api/computers/search"
    data = { "maxItems": 1, "searchCriteria": [ { "fieldName": "hostName", "stringTest": "equal", "stringValue": hostname } ] }
    post_header = { "Content-type": "application/json",
                    "api-secret-key": api_key,
                    "api-version": "v1"}
    response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

    raise ValueError(response)

    computer_id = 0

    # Error handling
    if 'message' in response:
        if response['message'] == "Invalid API Key":
            raise ValueError("Invalid API Key")

    return computer_id

def computer_present(hostname, group_id, dsm_url, api_key):
    '''
    Ensure computer to be present
    '''

    if search_computer(hostname, dsm_url, api_key) >= 0:
        url = dsm_url + "/api/computers"
        data = { "hostName": hostname, "description": "Created by Ansible", "groupID": group_id }
        post_header = { "Content-type": "application/json",
                        "api-secret-key": api_key,
                        "api-version": "v1"}
        response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

        # Error handling
        if 'message' in response:
            if response['message'] == "Invalid API Key":
                raise ValueError("Invalid API Key")

        # Computer created
        return 200

    # Computer already present
    return 201

def computer_absent(hostname, dsm_url, api_key):
    '''
    Ensure computer to be present
    '''

    computer_id = search_computer(hostname, group_id, dsm_url, api_key)

    if computer_id >= 0:

        url = dsm_url + "/api/computers/" + computer_id
        data = { }
        post_header = { "Content-type": "application/json",
                        "api-secret-key": api_key,
                        "api-version": "v1"}
        response = requests.delete(url, data=json.dumps(data), headers=post_header, verify=False).json()

        # Error handling
        if 'message' in response:
            if response['message'] == "Invalid API Key":
                raise ValueError("Invalid API Key")

        # Computer deleted
        return 200

    # Computer already absent
    return 201

def run_module():

    # Argument & parameter definitions
    module_args = dict(
        hostname=dict(type='str', required=True),
        state=dict(Type='str', required=True),
        group_id=dict(Type='int', required=False),
        dsm_url=dict(type='str', required=True),
        api_key=dict(type='str', required=True)
    )

    # Result dictionary
    result = dict(
        changed=False,
        message=''
    )

    # The AnsibleModule
    # We support check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # If in check mode return empty result set
    if module.check_mode:
        return result

    #
    # Module logic
    #
    # Build intrusion prevention ips rules CVEs dictionary
    task_result = 0
    if module.params['state'] == 'present':
        task_result = computer_present(module.params['hostname'], module.params['group_id'], module.params['dsm_url'], module.params['api_key'])
    elif module.params['state'] == 'absent':
        task_result = computer_absent(module.params['hostname'], module.params['dsm_url'], module.params['api_key'])
    else
        module.fail_json(msg="allowed states present or absent", **result)

    # Populate result set

    # We didn't change anything on the host
    if task_result == 200:
        result['changed'] = False
    else
        result['changed'] = True

    # Return key/value results
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
