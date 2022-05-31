#!/usr/bin/python3
"""
Part of RedELK

This check queries for requests that are identical to requests made from the customer network, but from a different IP.
It matches on 'http.headers.useragent', 'http.request.body.content', but those can be extended.

Authors:
- Matthijs Vos (@matthijsy)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_value, raw_search, add_tags_by_query
from config import alarms

info = {
    'version': 0.1,
    'name': 'Suspicious Beacon module',
    'alarmmsg': 'SUSPICIOUS BEACON CONNECTED TO C2_ backend',
    'description': 'This check queries for requests that are identical to requests made from the customer network, but from a different IP. '
                   'This could indicate that the malware is running somewhere unexpected, or in a AV sandbox.',
    'type': 'redelk_alarm',
    'submodule': 'alarm_potential_sandbox'
}


class Module():
    """ Suspicious Beacon module """

    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

        # How much time between 2 alerts from the same host
        # Default 2 hours
        self.backoff = alarms[info['submodule']]['backoff'] if info['submodule'] in alarms else 3600 * 2

        # The fields that make characterises a request.
        # This is used to match the known customer request to potential sandbox requests
        self.unique_fields = ['http.headers.useragent', 'http.request.body.content']

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', 'source.ip', 'source.nat.ip', 'source.geo.country_iso_code',
                         'source.as.organization.name', 'redir.frontend.name', 'redir.backend.name',
                         'infra.attack_scenario', 'tags', 'redir.timestamp']
        ret['groupby'] = ['source.ip']

        # 1. Lookup the existing characteristics from the customer IPs
        customer_characteristics = self.get_customer_characteristics()

        # 2. Query the same kind of requests
        report = self.alarm_check(customer_characteristics)

        # 3. Filter the request that are already alerted within the backoff
        report = self.filter_backoff(report)

        ret['hits']['hits'] = report
        ret['hits']['total'] = len(report)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def get_customer_characteristics(self):  # pylint: disable=no-self-use
        """ Returns the characteristics of the requests from the customer network """
        terms = [{"field": c} for c in self.unique_fields]
        es_query = {
            "query": {
                "bool": {
                    "must": {
                        "match": {
                            "tags": "iplist_customer"
                        }
                    }
                }},
            "aggs": {
                "characteristics": {
                    "multi_terms": {"terms": terms}
                }
            }
        }
        res = raw_search(es_query, index='redirtraffic-*')

        if res is None:
            return None

        result = []
        for c in res['aggregations']['characteristics']['buckets']:
            result.append({k: r for k, r in zip(self.unique_fields, c['key'])})

        return result

    def alarm_check(self, customer_characteristics):  # pylint: disable=no-self-use
        """ This check queries for all requests that have the same charasteristics, but are not a customer request """

        should = []
        for c in customer_characteristics:
            should.append({"bool": {
                "must": [{"match": {k: v}} for k, v in c.items()]
            }
            })

        es_query = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {'match': {'tags': 'enrich_iplists'}}
                    ],
                    'should': should,
                    'must_not': [
                        {
                            'query_string': {
                                'fields': ['tags'],
                                'query': 'iplist_customer'
                            }
                        },
                        {'wildcard': {'tags': f"*{info['submodule']}"}}
                    ],
                    "minimum_should_match": 1
                }
            }
        }

        res = raw_search(es_query, index='redirtraffic-*')
        if res is None:
            hits = []
        else:
            hits = res['hits']['hits']

        return hits

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
                            'range':  {
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

