#!/usr/bin/python
# -*- encoding: utf-8 -*-
#
# Returns a list of currently protected CVEs and Microsoft vulnerabilities.
# Example:
# python ds_protection_status.py <dnsname|ip>
#
# Uncomment below in order to disable SSL certificate validation.
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import sys
import json
import suds.client
import pickle
import os.path

DEEP_SECURITY_ENDPOINT = ''
DEEP_SECURITY_TENANT = '{{ ds_tenant }}'
DEEP_SECURITY_USER = ''
DEEP_SECURITY_PASSWORD = ''

# Fetch assigned IPS rules for all known hosts
# @param    rules_cves Lookup table with IPS rules and covered CVEs
def deep_security_hosts_retrieve_and_match(fwrule, hostname):
    dsm = suds.client.Client('{0}/webservice/Manager?WSDL'.format(DEEP_SECURITY_ENDPOINT))

#    sID = dsm.service.authenticateTenant(DEEP_SECURITY_TENANT, DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)
    sID = dsm.service.authenticate(DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)

    try:

        hosts = dsm.service.hostRetrieveAll(sID)
        for host in hosts:
            if host.name != hostname:
                continue

            print('host={0} (id={1})'.format(host.name, host.ID))

            # Fetch inherited IPS rules
            # Host Detail Level: HIGH MEDIUM LOW
            # EnumHostFilterType: ALL_HOSTS HOSTS_IN_GROUP HOSTS_USING_SECURITY_PROFILE HOSTS_IN_GROUP_AND_ALL_SUBGROUPS SPECIFIC_HOST MY_HOSTS
            host_detail = dsm.service.hostDetailRetrieve({'hostGroupID': None, 'hostID': host.ID, 'securityProfileID': None, 'type': 'SPECIFIC_HOST'}, 'HIGH', sID)

            # Check, if the host has a security profile assigned
            if host_detail[0].securityProfileID:
                # Get the security profile
                securityProfile = dsm.service.securityProfileRetrieve(host_detail[0].securityProfileID, sID)
                print('securiteProfile={0}'.format(securityProfile))

                # Retrieve firewall rule by given name
                firewallRule = dsm.service.firewallRuleRetrieveByName(fwrule, sID)

                # Assign FW rule to security profile
#                if not securityProfile.firewallRuleIDs:
                    #member = suds.client.factory.create('firewallRuleIDs')
#                    entry = suds.client.factory.create('item')
#                    securityProfile.firewallRuleIDs = entry
#.append({'item[]':'19'})
#                    print('securiteProfile={0}'.format(securityProfile))
#                    print('ruleids={0}'.format(securityProfile.firewallRuleIDs))
#                    for rule in securityProfile.firewallRuleIDs.item:
#                        print('rule={0}'.format(rule))

#                newFirewallRuleIDs = []

                if firewallRule.ID not in securityProfile.firewallRuleIDs.item:
                    # Create host specific security profile
                    newSecurityProfile = securityProfile
                    newSecurityProfile.firewallRuleIDs.item.append(firewallRule.ID)
                    newSecurityProfile.parentSecurityProfileID = securityProfile.ID
                    newSecurityProfile.name = securityProfile.name + " (Ansible modified for " + host.name + ")"
                    newSecurityProfile.ID = None
                    print('newSecuriteProfile={0}'.format(newSecurityProfile))
                    # Save new security profile
                    newSecurityProfile = dsm.service.securityProfileSave(newSecurityProfile, sID)
                    # Assign new security profile to host
                    dsm.service.securityProfileAssignToHost(newSecurityProfile.ID, host.ID, sID)
            break
    finally:
        dsm.service.endSession(sID)


def main():

    if len(sys.argv) == 6:
        global DEEP_SECURITY_ENDPOINT
        DEEP_SECURITY_ENDPOINT = 'https://' + sys.argv[3] + ':4119'
        global DEEP_SECURITY_USER
        DEEP_SECURITY_USER = sys.argv[4]
        global DEEP_SECURITY_PASSWORD
        DEEP_SECURITY_PASSWORD = sys.argv[5]

        print('Modify Policy for ' + sys.argv[2] + ' and adding firewall rule ' + sys.argv[1])
        deep_security_hosts_retrieve_and_match(sys.argv[1], sys.argv[2])
    else:
        print('target host name or ip required')
if __name__ == '__main__':
    main()
