#!/usr/bin/env python3

import argparse
import logging
import ssl
from elasticsearch import Elasticsearch
from elasticsearch.connection import create_ssl_context
from urllib3 import exceptions
import time
from estask import get_tasks, ESTask


def create_tls_context(ca_path=None, cert_path=None, key_path=None, key_pass=None):
    context = create_ssl_context()
    if ca_path != None:
        context.load_verify_locations(ca_path)
    if cert_path != None and key_path != None:
        context.load_cert_chain(
            certfile=cert_path, keyfile=key_path, password=key_pass)
    return context


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog=__file__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--timeout', type=int,
                        default=60, help='Search timeout')
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
    parser.add_argument('--local', dest='local', default=False,
                        help='Watch tasks only on connected node', action='store_true')
    parser.add_argument('--use-ssl', dest='use_ssl',
                        default=True, help='Use SSL', action='store_true')

    args = parser.parse_args()

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

    watch_nodes = None
    if args.local:
        watch_nodes = '_local'

    while True:
        node_tasks = get_tasks(es, nodes=watch_nodes)
        for task in node_tasks:
            print('id: {}'.format(task.task_id))
            print('\trunning: {}s'.format(task.running_seconds))
            print('\tdescription: {}'.format(task.description))
        print('-----------------------------------')
        time.sleep(10)
