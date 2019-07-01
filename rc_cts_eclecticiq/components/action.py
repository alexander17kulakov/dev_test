#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import requests
import json
import datetime
import logging
import resilient
import re
from circuits.core.handlers import handler
from resilient_circuits.actions_component import ResilientComponent, ActionMessage

LOG = logging.getLogger(__name__)

class MyExampleComponent(ResilientComponent):

    CONFIG_SECTION = "eclecticiq"

    def __init__(self, opts):
        super(MyExampleComponent, self).__init__(opts)
        LOG.debug(opts)
        self.options = opts.get(self.CONFIG_SECTION, {})
        self.eclecticiq_url = self._get_value_from_options("eclecticiq_url")
        self.eclecticiq_user = self._get_value_from_options("eclecticiq_user")
        self.eclecticiq_password = self._get_value_from_options("eclecticiq_password")
        self.eclecticiq_ssl_check = self._get_value_from_options("eclecticiq_ssl_check")
        self.sightings_group_name = self._get_value_from_options("sightings_group_name")

        self.headers = {
            'user-agent': "IBM Resilient",
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        self.api_path = {
            'auth_api_url': '/api/auth',
            'get_observable_api_url': '/api/observables',
            'get_entity_api_url': '/private/search-all',
            'get_group_uuid_api_url': '/private/groups/?filter[name]=',
            'create_sighting_api_url': '/private/entities/',
        }

        self.field_dict = {"Name": "incident['name']",
                  "Incident Type": "event.message[u'type_info'][u'incident'][u'fields'][u'incident_type_ids'][u'values']",
                  "NIST Attack Vectors": "event.message[u'type_info'][u'incident'][u'fields'][u'nist_attack_vectors'][u'values']",
                  "Owner": "event.message['type_info']['incident']['fields']['owner_id']['values']['1']['label']",
                  "Created By": "event.message[u'type_info']['incident']['fields']['creator_id']['values']['1']['label']",
                  "Date Created": "datetime.datetime.fromtimestamp(incident['create_date'] / 1000).strftime('%m/%d/%Y %H:%M:%S')",
                  "Date Occured": "datetime.datetime.fromtimestamp(incident['start_date'] / 1000).strftime('%m/%d/%Y %H:%M:%S')",
                  "Date Discovered": "datetime.datetime.fromtimestamp(incident[u'discovered_date'] / 1000).strftime('%m/%d/%Y %H:%M:%S')",
                  "Address": "incident['addr']",
                  "City": "incident['city']",
                  "Country": "event.message['type_info']['incident']['fields']['country']['values']['1000']['label']",
                  "State": "event.message['type_info']['incident']['fields']['state']['values']['1']['label']",
                  "ZIP Code": "incident['zip']",
                  "Resolution Summary": "incident['resolution_summary']",
                  "Description": "incident['description']"}

        self.order = ["Name", "Incident Type", "NIST Attack Vectors", "Date Created", "Date Occured", "Date Discovered", "Owner", "Created By", "Address", "City", "State", "Country", "ZIP Code", "Resolution Summary", "Description"]

        if self.eclecticiq_ssl_check == "False":
            self.eclecticiq_ssl_check = False
        else:
            self.eclecticiq_ssl_check = True


    channel = "actions.eclecticiq_sighting"

    @handler("create_sighting")
    def _test2(self, event, *args, **kwargs):

        # In the message we find the whole incident data (and other context)
        incident = event.message["incident"]
        inc_id = incident["id"]
        LOG.info("Called from incident {}: {}".format(incident["id"], incident["name"]))

        # Read connection parameters from your configuration file, supplemented from the command-line
        parser = resilient.ArgumentParser(config_file=resilient.get_config_file())
        opts = parser.parse_args()

        # Connect and authenticate to the Resilient organization, to get a SimpleClient
        client = resilient.get_client(opts)

        # Get a single incident
        uri = "/incidents/{}/artifacts?handle_format=names".format(inc_id)
        art = client.get(uri)

        artifacts = self._converter(art)

        details=self._get_details(event, self.field_dict, self.order)
        self._get_outh_token()
        self._create_sighting(self.sightings_group_name, details, artifacts, incident["name"])

        a="success"
        yield a

    def _get_field_info(self, event, det_dict, det_name):
        incident = event.message["incident"]
        try:
            if eval(det_dict[det_name]) is not None and det_name not in ["Incident Type", "NIST Attack Vectors", "Description", "Resolution Summary"]:
                return eval(det_dict[det_name])
            elif det_name in ["Incident Type", "NIST Attack Vectors"] and len(eval(det_dict[det_name])) != 0:
                item_str = str()
                for item in eval(det_dict[det_name]):
                    item_str += eval(det_dict[det_name])[item]["label"] + " | "
                item_str = item_str[:-2]
                return item_str
            elif det_name in ["Description", "Resolution Summary"]:
                return self._cleanhtml(eval(det_dict[det_name]))
            else:
                return "None"
        except:
            return "None"


    def _get_details(self, event, field_dict, order_list):

        details=str()
        for item in order_list:
            details += item + ": " + self._get_field_info(event, field_dict, item) + "<br>"
        return details



    def _cleanhtml(self, raw_html):
        patterns = [{"</div>": " "}, {"&nbsp;": " "}, {"<.*?>": ""}]
        cleantext = str(raw_html)
        for item in patterns:
            for key, value in item.iteritems():
                cleaner = re.compile(key)
                cleantext = re.sub(cleaner, value, cleantext)
        return cleantext

    def _converter(self, artifacts):
        check_dict = {"DNS Name": "domain", "Email Attachment Name": "file", "Email Recipient": "email", "Email Sender": "email", "Email Sender Name": "person", "Email Subject": "email", "File Name": "file", "IP Address": "ipv4", "Malware MD5 Hash": "hash-md5", "Malware SHA-1 Hash": "hash-sha1", "Malware SHA-256 Hash": "hash-sha256", "Mutex": "mnutex", "Port": "port", "Process Name": "process", "Registry Key": "winregistry", "System Name": "host", "URI Path": "uri", "URL": "uri", "URL Referer": "uri", "User Account": "name"}
        art_list=list()
        for item in artifacts:
            if item["type"] not in check_dict:
                continue
            else:
                t=check_dict.get(item["type"])
                art_dict = {"link_type": "sighted", "classification": "bad", "kind": t, "value": item["value"]}
                art_list.append(art_dict)
        return art_list

    def _add_artifacts_to_sighting(self, sighting, list_of_art):
        for item in list_of_art:
            for key, value in item.iteritems():
                obs = {
                    "link_type": "sighted",
                    "classification": "bad",
                    "kind": value,
                    "value": key
                }
            sighting['data']['meta']['manual_extracts'].append(obs)


    def _create_sighting(self, group_name, details, list_of_artifacts, inc_name):
        LOG.debug("Starting create_sighting from eiq_api.")

        source = self._get_source_group_uid(group_name)

        today = datetime.datetime.utcnow().date()

        today_begin = self.format_ts(datetime.datetime(today.year, today.month, today.day, 0, 0, 0))

        ts = self.format_ts(datetime.datetime.utcnow())

        title = "Resilient CTS Sighting - " + inc_name

        LOG.info("Creating sighting for incident {}".format(inc_name))

        sighting = {"data": {
            "data": {
                "confidence": {
                    "type": "confidence",
                    "value": "Medium"
                },
                "description": details,
                "description_structuring_format": "html",
                "type": "eclecticiq-sighting",
                "title": title,
                "security_control": {
                    "type": "information-source",
                    "identity": {
                        "name": "EclecticIQ Platform App for IBM Resilient",
                        "type": "identity"
                    },
                    "time": {
                        "type": "time",
                        "start_time": today_begin,
                        "start_time_precision": "second"
                    }
                },
            },
            "meta": {
                "manual_extracts": [],
                "taxonomy": [],
                "estimated_threat_start_time": ts,
                "tags": ["Resilient Custom Threat Service sighting"],
                "ingest_time": ts
            },
            "sources": [{
                "source_id": source
            }]
        }}

        sighting['data']['meta']['manual_extracts']=list_of_artifacts
        sightings_path = self.eclecticiq_url + self.api_path["create_sighting_api_url"]

        self._send_api_request(
            'post',
            path=sightings_path,
            data=sighting)

    def format_ts(self, dt):
        return dt.replace(microsecond=0).isoformat() + 'Z'


    def _get_source_group_uid(self, group_name):
        LOG.info(
            "Requesting source id for specified group, "
            "name=[" + str(group_name) + "]")

        group_path = self.eclecticiq_url + self.api_path["get_group_uuid_api_url"]

        r = self._send_api_request(
            'get',
            path=group_path,
            params='filter[name]=' + str(group_name))

        if not r.json()['data']:
            LOG.error(
                'Something went wrong fetching the group id. '
                'Please note the source group name is case sensitive! '
                'Received response:' + str(r.json()))
            return "error_in_fetching_group_id"
        else:
            LOG.info('Source group id received')
            LOG.debug(
                'Source group id is: ' + str(r.json()['data'][0]['source']))
            return r.json()['data'][0]['source']

    def _send_api_request(self, method, path, params=None, data=None):
        """
        Request wrapper for EclecticIQ Platform
        """
        r = None
        try:
            if method == 'post':
                r = requests.post(
                    path,
                    headers=self.headers,
                    params=params,
                    data=json.dumps(data),
                    verify=self.eclecticiq_ssl_check
                )
            elif method == 'get':
                r = requests.get(
                    path,
                    headers=self.headers,
                    params=params,
                    data=json.dumps(data),
                    verify=self.eclecticiq_ssl_check
                )
            else:
                LOG.error("Unknown method: " + str(method))
                raise Exception
        except Exception:
            LOG.error('Could not perform request to EclecticIQ VA: {}: {}'.format(method, path))

        if r and r.status_code in [100, 200, 201]:
            return r
        else:
            if not r:
                msg = ('Could not perform request to EclecticIQ VA: {}: {}'
                       .format(method, path))
                LOG.error(msg)
                raise Exception(msg)
            try:
                err = r.json()
                detail = err['errors'][0]['detail']
                msg = ('EclecticIQ VA returned an error, '
                       'code:[{0}], reason:[{1}], URL: [{2}], details:[{3}]'
                       .format(
                           r.status_code,
                           r.reason,
                           r.url,
                           detail))
            except Exception:
                msg = ('EclecticIQ VA returned an error, '
                       'code:[{0}], reason:[{1}], URL: [{2}]').format(
                    r.status_code,
                    r.reason,
                    r.url)
            raise Exception(msg)

    def _get_outh_token(self):
        LOG.info('Authenticating using username: ' + str(self.eclecticiq_user))

        outh_path = self.eclecticiq_url + self.api_path["auth_api_url"]

        try:
            r = self._send_api_request(
                'post',
                path=outh_path,
                data={
                    'username': self.eclecticiq_user,
                    'password': self.eclecticiq_password
                }
            )
            self.headers['Authorization'] = 'Bearer ' + r.json()['token']
            LOG.info('Authentication is successful')
        except Exception:
            LOG.error("Authentication failed")
            raise

    def _get_value_from_options(self, app_config_setting_key):
        """
        Get value from options dict or raise ValueError for the mandatory config setting.
        :param app_config_setting_key key
        """
        if app_config_setting_key in self.options:
            return self.options[app_config_setting_key]
        else:
            error_msg = "Mandatory config setting '{}' not set.".format(app_config_setting_key)
            LOG.error(error_msg)
            raise ValueError(error_msg)