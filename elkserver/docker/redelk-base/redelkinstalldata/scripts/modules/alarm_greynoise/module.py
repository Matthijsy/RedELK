#!/usr/bin/python3
"""
Part of RedELK

This check queries for request that have a greynoise classification other then 'unknown' do talk to c2* paths on redirectors

Authors:
- Matthijs Vos (@matthijsy)
"""
import logging

from modules.helpers import get_initial_alarm_result, get_query

info = {
    'version': 0.1,
    'name': 'Greynoise module',
    'alarmmsg': 'VISIT FROM GREYNOISE CLASSIFIED IP TO C2_*',
    'description': 'This check queries for request that have a greynoise classification other then unknown do talk to c2* paths on redirectors',
    'type': 'redelk_alarm',
    'submodule': 'alarm_greynoise'
}


class Module():
    """ Greynoise module """

    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        """ Run the alarm module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        ret['fields'] = ['agent.hostname', '@timestamp', 'source.ip', 'greynoise.classification', 'greynoise.message',
                         'redir.frontend.name', 'redir.backend.name', 'infra.attack_scenario']
        ret['groupby'] = ['source.ip']
        report = self.alarm_check()
        ret['hits']['hits'] = report['hits']
        ret['hits']['total'] = len(report['hits'])
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def alarm_check(self):  # pylint: disable=no-self-use
        es_query = 'tags:enrich_greynoise AND NOT greynoise.classification:unknown AND NOT tags:alarm_greynoise'
        es_results = get_query(es_query, 10000)

        return {"hits": es_results}
