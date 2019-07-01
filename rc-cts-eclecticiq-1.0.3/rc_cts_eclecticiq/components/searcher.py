#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import logging
import requests
import json
import urllib
import datetime

from circuits import BaseComponent, handler
from rc_cts import searcher_channel, Hit, NumberProp, StringProp, U riProp

LOG = logging.getLogger(__name__)


class EclecticIQLookup(BaseComponent):

    CONFIG_SECTION = "eclecticiq"

    def __init__(self, opts):
        super(EclecticIQLookup, self).__init__(opts)
        LOG.debug(opts)
        self.options = opts.get(self.CONFIG_SECTION, {})
        self.eclecticiq_url = self._get_value_from_options("eclecticiq_url")
        self.eclecticiq_user = self._get_value_from_options("eclecticiq_user")
        self.eclecticiq_password = self._get_value_from_options("eclecticiq_password")
        self.eclecticiq_ssl_check = self._get_value_from_options("eclecticiq_ssl_check")

        self.sightings_auto_creation = self._get_value_from_options("sightings_auto_creation")
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

        if self.eclecticiq_ssl_check == "False":
            self.eclecticiq_ssl_check = False
        else:
            self.eclecticiq_ssl_check = True

        if self.sightings_auto_creation == "False":
            self.sightings_auto_creation = False
        else:
            self.sightings_auto_creation = True

    # Register this as an async searcher for the URL /<root>/example
    channel = searcher_channel("eiq")

    @handler("net.ip", "net.name", "email", "email.header", "email.header.sender_address", "email.header.to", "hash.md5", "hash.sha1", "hash.sha256", "hash.sha512", "net.uri", "net.uri.path")
    def _lookup(self, event, *args, **kwargs):

        # Auth EIQ platform
        self._get_outh_token()

        # event.artifact is a ThreatServiceArtifactDTO
        artifact_type = event.artifact['type']
        artifact_value = event.artifact['value']
        LOG.info("_lookup started for Artifact Type {0} - Artifact Value {1}".format(artifact_type, artifact_value))

        # Generate request to Platform and get response in the hits dict

        hits = {}
        hits = self._get_observable_info(artifact_type, artifact_value)

        # If auto sighting creation is True and response returned some data - generate Sighting in Platform
        if self.sightings_auto_creation == True and hits is not None:
            record = {}
            record['type_eiq'] = self.value_request_type
            record['value_eiq'] = event.artifact['value']
            self._create_sighting(self.sightings_group_name, record)
        else:
            pass

        yield hits

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

    def _get_observable_info(self, value_type, value):
        LOG.info('Requesting Observable information for: ' + str(value_type) + " " + str(value))

        if value_type in ["net.ip"]:
            self.value_request_type = "ipv4"
        elif value_type in ["net.name"]:
            self.value_request_type = "domain"
        elif value_type in ["email", "email.header", "email.header.sender_address", "email.header.to"]:
            self.value_request_type = "email"
        elif value_type in ["hash.md5"]:
            self.value_request_type = "hash-md5"
        elif value_type in ["hash.sha1"]:
            self.value_request_type = "hash-sha1"
        elif value_type in ["hash.sha256"]:
            self.value_request_type = "hash-sha256"
        elif value_type in ["hash.sha512"]:
            self.value_request_type = "hash-sha512"
        elif value_type in ["net.uri", "net.uri.path"]:
            self.value_request_type = "uri"
        else:
            return

        obs_path = self.eclecticiq_url + self.api_path["get_observable_api_url"] + "?filter[type]=" + self.value_request_type + '&filter[value]=' + urllib.quote_plus(value)

        r = self._send_api_request(
            'get',
            path=obs_path,
        )

        observabl_response = json.loads(r.text)

        if observabl_response["total_count"] > 0:
            maliciousness = observabl_response["data"][0]["meta"]["maliciousness"]
            last_updated = observabl_response["data"][0]["last_updated_at"]
            platform_link = self.eclecticiq_url + "/observables/" + self.value_request_type + "/" + urllib.quote_plus(value)
        else:
            return

        indicator_path = self.eclecticiq_url + self.api_path["get_entity_api_url"] + '?q=extracts.value:"' + urllib.quote_plus(value) + '"&type=indicator'
        rr = self._send_api_request(
            'get',
            path=indicator_path,
        )

        indicator_response = json.loads(rr.text)

        if indicator_response["hits"]["total"] > 0:
            entity_name = ''
            for k in range(0, indicator_response["hits"]["total"]):
                if k is not 0:
                    entity_name += ", "
                entity_name += indicator_response["hits"]["hits"][k]["_source"]["data"]["title"]
        else:
            entity_name = "N/A"
            pass

        return Hit(
            StringProp(name="Connected Entities", value=entity_name),
            StringProp(name="Last Updated", value=last_updated),
            StringProp(name="Maliciousness", value=maliciousness),
            UriProp(name="EclecticIQ Platform Link", value=platform_link))

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

    def format_ts(self, dt):
        return dt.replace(microsecond=0).isoformat() + 'Z'

    def _create_sighting(self, group_name, record):
        LOG.debug("Starting create_sighting from eiq_api.")

        extract_kind = record['type_eiq']
        extract_value = record['value_eiq']

        source = self._get_source_group_uid(group_name)

        today = datetime.datetime.utcnow().date()

        today_begin = self.format_ts(datetime.datetime(today.year, today.month, today.day, 0, 0, 0))
        today_end = self.format_ts(datetime.datetime(today.year, today.month, today.day, 23, 59, 59))

        ts = self.format_ts(datetime.datetime.utcnow())

        title = "Resilient CTS Sighting - " + str(extract_kind) + ":" + str(extract_value)

        LOG.info("Creating sighting for record {0}:{1}".format(extract_kind, extract_value))

        sighting = {"data": {
            "data": {
                "confidence": {
                    "type": "confidence",
                    "value": "Medium"
                },
                "description": "Sighting created by IBM Resilient Custom Threat Service",
                "description_structuring_format": "html",
                "type": "eclecticiq-sighting",
                "title": title,
                "security_control": {
                    "type": "information-source",
                    "identity": {
                        "name": "EclecticIQ Platform App for Splunk",
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
                "manual_extracts": [
                    {
                        "link_type": "sighted",
                        "classification": "bad",
                        "kind": extract_kind,
                        "value": extract_value
                    }
                ],
                "taxonomy": [],
                "estimated_threat_start_time": ts,
                "tags": ["Resilient Custom Threat Service sighting"],
                "ingest_time": ts
            },
            "sources": [{
                "source_id": source
            }]
        }}

        sightings_path = self.eclecticiq_url + self.api_path["create_sighting_api_url"]

        self._send_api_request(
            'post',
            path=sightings_path,
            data=sighting)