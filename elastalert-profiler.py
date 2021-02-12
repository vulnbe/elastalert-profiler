#!/usr/bin/env python3

import argparse
import logging
from datetime import datetime, timedelta
import ssl
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
import yaml
import os
from urllib3 import exceptions
from hashlib import sha256
from estask import get_tasks, ESTask
import time


def create_tls_context(ca_path=None, cert_path=None, key_path=None, key_pass=None):
    context = create_ssl_context()
    if ca_path != None:
        context.load_verify_locations(ca_path)
    if cert_path != None and key_path != None:
        context.load_cert_chain(
            certfile=cert_path, keyfile=key_path, password=key_pass)
    return context


def profileQuery(es, query, timeout=60, scroll='5m', index=None):
    took = 0
    tag = sha256(yaml.dump(query).encode('utf-8')).hexdigest()
    try:
        page = es.search(index=index, body=query, params={
                         'scroll': scroll, 'size': 5000, 'stats': tag})
        took += page['took']
        sid = page['_scroll_id']
        hitsTotal = page['hits']['total']
        hits = len(page['hits']['hits'])
        while hits > 0:
            page = es.scroll(scroll_id=sid, params={'scroll': scroll})
            took += page['took']
            hits = len(page['hits']['hits'])
            sid = page['_scroll_id']
        logging.info("\t{} docs, {} took".format(hitsTotal, took))
    except Exception as ex:
        took = timeout * 1000
        tasks = get_tasks(es, nodes='_local')
        for task in tasks:
            if tag in task.description:
                start_time = datetime.now()
                took = task.running_seconds * 1000
                task.cancel(cancel_children=True, wait_for_exit=True)
                td = datetime.now() - start_time
                took += (td.total_seconds() * 1000)
                break
        logging.error('Got error while processing tag {}'.format(tag))
    return took


def make_time_range_query(query, time_field='@timestamp', duration='15m'):
    _query = {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            time_field: {
                                "gte": "now-{}".format(duration),
                                "lte": "now"
                            }
                        }
                    },
                    query
                ]
            }
        }
    }
    return _query


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--timeout', type=int,
                        default=60, help='Search timeout')
    parser.add_argument('--query-window', type=str, dest='query_window',
                        default="15m", help='Query window')
    parser.add_argument('--time-field', type=str, dest='time_field',
                        default="@timestamp", help='Name of time field to query results')
    parser.add_argument('--scroll', type=str, dest='scroll',
                        default="5m", help='Scroll duration')
    parser.add_argument('--rule-dir', type=str, dest='rule_dirs', required=True,
                        help='Path to elastalert ruleset [multiple --rule-dir supported]', action='append')
    parser.add_argument('--node', type=str, dest='nodes', required=True,
                        help='ElasticSearch node [multiple --node supported]', action='append')
    parser.add_argument('--ca', type=str, required=False, help='CA file path')
    parser.add_argument('--cert', type=str, required=False,
                        help='Certificate file path')
    parser.add_argument('--key', type=str, required=False,
                        help='Key file path')
    parser.add_argument('--verbose', dest='verbose', default=False,
                        help='Increase verbosity', action='store_true')
    parser.add_argument('--use-ssl', dest='use_ssl',
                        default=True, help='Use SSL', action='store_true')

    args = parser.parse_args()

    results = []

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.ERROR)

    ssl_context = None
    if args.ca != None or (args.cert != None and args.key != None):
        ssl_context = create_tls_context(ca_path=args.ca, cert_path=args.cert,
                                         key_path=args.key)

    es = Elasticsearch(args.nodes, timeout=args.timeout, use_ssl=args.use_ssl, verify_certs=args.use_ssl,
                       ca_certs=args.ca, client_cert=args.cert, client_key=args.key)

    for ruleset_path in args.rule_dirs:
        for maybe_file in os.listdir(ruleset_path):
            if maybe_file.endswith(".yaml") or maybe_file.endswith(".yml"):
                filename = os.path.join(ruleset_path, maybe_file)
                logging.info('Profiling {} rule'.format(filename))
                with open(filename, 'r') as rule_file:
                    rule = yaml.safe_load(rule_file)
                    index = None
                    if 'index' in rule.keys():
                        index = rule['index']
                    if 'filter' in rule.keys():
                        took = 0
                        for query in rule['filter']:
                            _query = make_time_range_query(
                                query['query'], time_field=args.time_field, duration=args.query_window)
                            took += profileQuery(es, _query, timeout=args.timeout,
                                                 scroll=args.scroll, index=index)
                        results.append({'rule': filename, 'took': took})
    sorted_results = sorted(results, key=lambda res: res['took'], reverse=True)
    for result in sorted_results:
        print('{}: {}'.format(round(result['took']), result['rule']))
