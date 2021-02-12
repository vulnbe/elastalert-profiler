# Elasticsearch query profiler designed for elastalert ruleset

## Usage

```
elastalert-profiler.py [-h] [--timeout TIMEOUT] [--query-window QUERY_WINDOW] [--time-field TIME_FIELD] [--scroll SCROLL] --rule-dir RULE_DIRS --node NODES
                                                                  [--ca CA] [--cert CERT] [--key KEY] [--verbose] [--use-ssl]

optional arguments:
  -h, --help            show this help message and exit
  --timeout TIMEOUT     Search timeout (default: 60)
  --query-window QUERY_WINDOW
                        Query window (default: 15m)
  --time-field TIME_FIELD
                        Name of time field to query results (default: @timestamp)
  --scroll SCROLL       Scroll duration (default: 5m)
  --rule-dir RULE_DIRS  Path to elastalert ruleset [multiple --rule-dir supported] (default: None)
  --node NODES          ElasticSearch node [multiple --node supported] (default: None)
  --ca CA               CA file path (default: None)
  --cert CERT           Certificate file path (default: None)
  --key KEY             Key file path (default: None)
  --verbose             Increase verbosity (default: False)
  --use-ssl             Use SSL (default: True)
```

## Examples

Watching node tasks:

`./watch_tasks.py --node https://some_node:9200 --rule-dir ./elastalert-rules --cert cert.pem --key key.pem --ca ca.pem`

Profiling ruleset:

`./elastalert-profiler.py --node https://some_node:9200 --rule-dir ./elastalert-rules --cert cert.pem --key key.pem --ca ca.pem `
