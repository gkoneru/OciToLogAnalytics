#!/usr/bin/env python
# coding: utf-8

# In[50]:


import json
import requests
import datetime
import hashlib
import hmac
import base64
import oci


# In[52]:


# Set up OCI config
config = oci.config.from_file(
     "/Users/vg/Downloads/config",
     "DEFAULT")
# Create a service client
identity = oci.identity.IdentityClient(config)
# Get the current user
user = identity.get_user(config["user"]).data
# print(user)



# coding: utf-8
# Copyright (c) 2016, 2020, Oracle and/or its affiliates.  All rights reserved.
# This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.

#  This script retrieves all audit logs across an Oracle Cloud Infrastructure Tenancy.
#  for a timespan defined by start_time and end_time.
#  This sample script retrieves Audit events for last 5 days.
#  This script will work at a tenancy level only.

def get_subscription_regions(identity, tenancy_id):
    '''
    To retrieve the list of all available regions.
    '''
    list_of_regions = []
    list_regions_response = identity.list_region_subscriptions(tenancy_id)
    for r in list_regions_response.data:
        list_of_regions.append(r.region_name)
    return list_of_regions


def get_compartments(identity, tenancy_id):
    '''
    Retrieve the list of compartments under the tenancy.
    '''
    list_compartments_response = oci.pagination.list_call_get_all_results(
        identity.list_compartments,
        compartment_id=tenancy_id).data

    compartment_ocids = [c.id for c in filter(lambda c: c.lifecycle_state == 'ACTIVE', list_compartments_response)]

    return compartment_ocids


def get_audit_events(customer_id, shared_key, audit, compartment_ocids, start_time, end_time):
    '''
    Get events iteratively for each compartment defined in 'compartments_ocids'
    for the region defined in 'audit'.
    This method eagerly loads all audit records in the time range and it does
    have performance implications of lot of audit records.
    Ideally, the generator method in oci.pagination should be used to lazily
    load results.
    '''
    list_of_audit_events = []
    log_type = 'OCIAudit'
    for c in compartment_ocids:
        list_events_response = oci.pagination.list_call_get_all_results(
#         list_events_response = oci.pagination.list_call_get_all_results_generator(
            audit.list_events,
            compartment_id=c,
            start_time=start_time,
            end_time=end_time).data
        #  Results for a compartment 'c' for a region defined
        #  in 'audit' object.
        list_of_audit_events.extend(list_events_response)
        
    return list_of_audit_events

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8") 
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'
    print('URI : ' + uri)
    print('Log Type :' + log_type)
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print(response.text)

#  Setting configuration
#  Default path for configuration file is "~/.oci/config"
config = oci.config.from_file("/Users/vg/Downloads/config")
tenancy_id = config["tenancy"]

#  Initiate the client with the locally available config.
identity = oci.identity.IdentityClient(config)

#  Timespan defined by variables start_time and end_time(today).
#  ListEvents expects timestamps into RFC3339 format.
#  For the purposes of sample script, logs of last 5 days.
end_time = datetime.datetime.utcnow()

###NEED TO ADD LOGIC ###
# Will eventually ARM query Log Analytics for lastest date/time in OCIAudit table and pass.
start_time = end_time + datetime.timedelta(days=-30)

# This array will be used to store the list of available regions.
regions = get_subscription_regions(identity, tenancy_id)

# This array will be used to store the list of compartments in the tenancy.
compartments = get_compartments(identity, tenancy_id)

audit = oci.audit.audit_client.AuditClient(config)

# Update the customer ID to your Log Analytics workspace ID
customer_id = 'xxxxxxxxxxxxxxxx'

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "xxxxxxxxxxxxxxxxxx"

log_type = 'OCIAuditgk'



#  For each region get the logs for each compartment.
for r in regions:
    #  Intialize with a region value.
    audit.base_client.set_region(r)
    #  To separate results by region use print here.
    audit_events = get_audit_events(customer_id,
        shared_key,
        audit,
        compartments,
        start_time,
        end_time)

# Push results to loganalytics. 

for event in audit_events:
    jsondoc = json.loads(str(event))
    parsed_json = json.dumps(jsondoc, indent=4, sort_keys=True)
    post_data(customer_id, shared_key, parsed_json, log_type)
