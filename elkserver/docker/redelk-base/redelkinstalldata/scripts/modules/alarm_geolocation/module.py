#!/usr/bin/python3
"""
Part of RedELK

This check queries for geolocations that are not listed in any allowlist_geolocations.conf and do talk to c2* paths on redirectors

Authors:
- Matthijs Vos (@matthijsy)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_query, raw_search, add_tags_by_query
from config import alarms

info = {
    'version': 0.1,
    'name': 'Geolocation module',
    'alarmmsg': 'VISIT FROM INCORRECT GEOLOCATION TO C2_*',
    'description': 'This check queries for geolocations that are not listed in any allowlist_geolocations.conf and do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',
    'submodule': 'alarm_geolocation'
}


class Module():
    """ Geolocation module """

    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

        # How much time between 2 alerts from the same host
        # Default 2 hours
        self.backoff = alarms[info['submodule']]['backoff'] if info['submodule'] in alarms else 3600 * 2

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', '@timestamp', 'source.ip', 'source.geo.country_iso_code', 'source.nat.ip',
                         'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario']
        ret['groupby'] = ['source.ip', 'source.geo.country_iso_code']
        report = self.alarm_check()
        report = self.filter_backoff(report)
        ret['hits']['hits'] = report
        ret['hits']['total'] = len(report)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def alarm_check(self):  # pylint: disable=no-self-use
        """ This check queries for geolocations that are not listed in allowlist_geolocation.conf and do talk to c2* paths on redirectors"""
        file_name = '/etc/redelk/allowlist_geolocation.conf'
        with open(file_name, encoding='utf-8') as file:
            content = file.readlines()
        geolocs = [line.strip() for line in content if not line.startswith('#')]
        es_geo_filter = 'NOT (source.geo.country_iso_code:' + ' OR source.geo.country_iso_code:'.join(geolocs) + ')'
        es_query = f'{es_geo_filter} AND redir.backend.name:c2* AND NOT tags:*alarm_geolocation'

        es_results = get_query(es_query, 10000)

        return es_results

    def filter_backoff(self, records):
        if records == [] or self.backoff <= 0:
            return records

        # Check which IPs are already alerted
        es_query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {'match': {'tags': info['submodule']}},
                        {
                            'range': {
                                '@timestamp': {
                                    'gte': f'now-{self.backoff}s',
                                    'lte': 'now'
                                }
                            }
                        }
                    ],
                    'must': [
                        {'match': {'source.ip': record['_source']['source']['ip']}}
                        for record in records
                    ]
                }
            }
        }
        res = raw_search(es_query, index='redirtraffic-*')
        if not res:
            return records

        alerted_ips = [r['_source']['source']['ip'] for r in res['hits']['hits']]

        # Get the records that we want to skip
        skip_records = [r for r in records if r['_source']['source']['ip'] in alerted_ips]
        self.mark_skipped(skip_records)

        # Filter the records that are already alerted in the backoff period
        return [r for r in records if r['_source']['source']['ip'] not in alerted_ips]

    def mark_skipped(self, records):
        es_query = {
            'bool': {
                'filter': [
                    {'match': {'_id': r['_id']}},
                ] for r in records
            }
        }

        add_tags_by_query([f"skip_{info['submodule']}"], es_query, 'redirtraffic-*')
