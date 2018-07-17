#!/usr/bin/python
# -*- encoding: utf-8 -*-

# Uncomment below in order to disable SSL certificate validation.
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import sys
import json
import suds.client
import pickle
import os.path

DEEP_SECURITY_ENDPOINT = 'https://starfleet-dsm.hopto.org:4119'
DEEP_SECURITY_TENANT = '{{ ds_tenant }}'
DEEP_SECURITY_USER = ''
DEEP_SECURITY_PASSWORD = ''

# Fetch all IPS rules availble within DS and print
def deep_security_dpi_rules_retrieve_print():
    dsm = suds.client.Client('{0}/webservice/Manager?WSDL'.format(DEEP_SECURITY_ENDPOINT))

#    sID = dsm.service.authenticateTenant(DEEP_SECURITY_TENANT, DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)
    sID = dsm.service.authenticate(DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)

    try:

        print(' [*] Loading IPS Rules...')
        recommends = set()
        rules = dsm.service.DPIRuleRetrieveAll(sID)
        for rule in rules:
            if rule.cveNumbers:
                for cve in rule.cveNumbers.split(','):
                    print('{0},{1},{2}'.format(rule.identifier, rule.name, cve.strip()))
            if rule.msNumbers:
                for ms in rule.msNumbers.split(','):
                    print('{0},{1},{2}'.format(rule.identifier, rule.name, ms.strip()))
    finally:
        dsm.service.endSession(sID)

# Fetch all IPS rules availble i within DS and build Rule-CVE/MS-lookup table
# @return   rules_cves
def deep_security_dpi_rules_retrieve_build_id_cvemslist():

    rules_cves = {}

    dsm = suds.client.Client('{0}/webservice/Manager?WSDL'.format(DEEP_SECURITY_ENDPOINT))

#    sID = dsm.service.authenticateTenant(DEEP_SECURITY_TENANT, DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)
    sID = dsm.service.authenticate(DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)

    try:

        print(' [*] Loading IPS Rules...')
        rules = dsm.service.DPIRuleRetrieveAll(sID)
        print(' [*] Building Rule-ID-CVE/MS Table...')
        for rule in rules:
            # add msNumbers here...
            cves = set()

            if rule.cveNumbers:
                for cve in rule.cveNumbers.split(','):
                    cves.add(str(cve.strip()))
            if rule.msNumbers:
                for ms in rule.msNumbers.split(','):
                    cves.add(str(ms.strip()))

            cves = sorted(cves)
            rules_cves[str(rule.ID).strip()] = cves

    finally:
        dsm.service.endSession(sID)

    # dump table to file
    with open('rules_cves.cache', 'wb') as fp:
        pickle.dump(rules_cves, fp)

    return rules_cves

# Search for a specific CVE within the dpi rules identifier cvems lookup table
# @param   rules_cves
# @param   cve
def deep_security_dpi_rules_search_cve(rules_cves, cve):
    dsm = suds.client.Client('{0}/webservice/Manager?WSDL'.format(DEEP_SECURITY_ENDPOINT))

#    sID = dsm.service.authenticateTenant(DEEP_SECURITY_TENANT, DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)
    sID = dsm.service.authenticate(DEEP_SECURITY_USER, DEEP_SECURITY_PASSWORD)

    try:
        for rule in rules_cves:
            if str(cve) in rules_cves[str(rule)]:
                print('{0} covers {1} - {2}'.format(dsm.service.DPIRuleRetrieve(rule, sID).identifier, cve, rules_cves[str(rule)]))

    finally:
        dsm.service.endSession(sID)


#        if str(ruleID) in rules_cves:
#             cves.update(rules_cves[str(ruleID)])


# Recursively fetch assigned IPS rules within policy hierarchy
# @param    securityProfileID Policy
# @param    rules Growing IPS rule set
# @param    dsm DSM instance
# @param    sID DSM session ID
# @param    rules
def get_inherited_dpi_rules_by_securityProfileID(securityProfileID, rules, dsm, sID):

    try:
        securityProfileID_detail = dsm.service.securityProfileRetrieve(securityProfileID, sID)

        if securityProfileID_detail.DPIRuleIDs:
            for rule in securityProfileID_detail.DPIRuleIDs.item:
                rules.add(dsm.service.DPIRuleRetrieve(rule, sID).identifier)

        if securityProfileID_detail.parentSecurityProfileID:
            get_inherited_dpi_rules_by_securityProfileID(securityProfileID_detail.parentSecurityProfileID, rules, dsm, sID)
    finally:
        return rules

# Fetch assigned IPS rules for all known hosts
# @param    rules_cves Lookup table with IPS rules and covered CVEs
def deep_security_hosts_retrieve_and_match(rules_cves, hostname):
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
                rules_inherited = set()
                rules_inherited = get_inherited_dpi_rules_by_securityProfileID(host_detail[0].securityProfileID, rules_inherited, dsm, sID)
                print('profileId={0}; ipsRulesByPolicy={1}'.format(host_detail[0].securityProfileID, rules_inherited))

                # Fetch assigned rules by recommendation scan
                # EnumRuleType: APPLICATIONTYPE, PAYLOADFILTER = 2, FIREWALLRULE, INTEGRITYRULE, LOGINSPECTIONRULE
                rules_recommended = set()
                rules_recommended = dsm.service.hostRecommendationRuleIDsRetrieve(host.ID, 2, False, sID)
                rules_unassigned = set()
                rules_unassigned = dsm.service.hostRecommendationRuleIDsRetrieve(host.ID, 2, True, sID)

                una = set()
                for r in rules_unassigned:
#                    print('ruleId={0} is unassigned'.format(dsm.service.DPIRuleRetrieve(r, sID).identifier))
                    una.add(dsm.service.DPIRuleRetrieve(r, sID).identifier)
                    rules_recommended.remove(r)
                print('unassigned={0}'.format(una))

                # Join
                rules = set()
                for r in rules_inherited:
                    rules.add(str(r))
                for r in rules_recommended:
                    rules.add(str(r))

                # Extract CVEs and MSIDs
                cves = set()
                for ruleID in rules:
                    if str(ruleID) in rules_cves:
                        cves.update(rules_cves[str(ruleID)])

                cves = sorted(cves)
                print('covered={0}'.format(cves))
            break
    finally:
        dsm.service.endSession(sID)


def main():

    if len(sys.argv) > 0:
        if sys.argv[1] == "-h":
            print('Help for ds_ipstools.py')
            print('Call with python3 ds_ipstools.py <param>')
            print(' -h             This brief help')
            print(' -p             List all currently covered CVEs and MSids and their IPS rules within DS')
            print(' -s <IDs...>    Search for IPS rules relevant for given CVEs and / or MSids')
            print(' -l             List current protection status of a computer object')
        if sys.argv[1] == "-s":
            rules_cves = {}
            if os.path.isfile('rules_cves.cache'):
                with open('rules_cves.cache', 'rb') as fp:
                    rules_cves = pickle.load(fp)
            else:
                rules_cves = deep_security_dpi_rules_retrieve_build_id_cvemslist()
            for index in range(len(sys.argv)-2):
                print('Searching for {0}'.format(str(sys.argv[index+2])))
                deep_security_dpi_rules_search_cve(rules_cves, str(sys.argv[index+2]))
        if sys.argv[1] == "-l":
            rules_cves = {}
            if os.path.isfile('rules_cves.cache'):
                with open('rules_cves.cache', 'rb') as fp:
                    rules_cves = pickle.load(fp)
            else:
                rules_cves = deep_security_dpi_rules_retrieve_build_id_cvemslist()
            deep_security_hosts_retrieve_and_match(rules_cves, sys.argv[2])
        if sys.argv[1] == "-p":
            deep_security_dpi_rules_retrieve_print()
if __name__ == '__main__':
    main()
