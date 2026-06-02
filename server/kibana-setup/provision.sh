#!/bin/sh
set -e

KIBANA_URL="https://kibana:5601"
ES_URL="https://elasticsearch:9200"
CACERT="/certs/ca/ca.crt"
AUTH="elastic:${ELASTIC_PASSWORD}"
DV_ID="prodepa-data-view"

log() { echo "[provision] $*"; }

# ---------------------------------------------------------------------------
wait_for_kibana() {
    log "Waiting for Kibana to reach green status..."
    until curl -sf --cacert "$CACERT" -u "$AUTH" \
            "${KIBANA_URL}/api/status" 2>/dev/null \
        | grep -q '"state":"green"'; do
        sleep 10
    done
    log "Kibana is ready."
}

# ---------------------------------------------------------------------------
create_index_template() {
    log "Creating Elasticsearch index template for prodepa-logs-*..."
    curl -sf -X PUT --cacert "$CACERT" -u "$AUTH" \
        "${ES_URL}/_index_template/prodepa-logs" \
        -H "Content-Type: application/json" \
        -d '{
  "index_patterns": ["prodepa-logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp":           { "type": "date" },
        "Source address":       { "type": "ip" },
        "Destination address":  { "type": "ip" },
        "NAT source IP":        { "type": "ip" },
        "NAT destination IP":   { "type": "ip" },
        "Source Port":          { "type": "integer" },
        "Destination Port":     { "type": "integer" },
        "Bytes":                { "type": "long" },
        "Bytes Sent":           { "type": "long" },
        "Bytes Received":       { "type": "long" },
        "Packets":              { "type": "long" },
        "Packets Sent":         { "type": "long" },
        "Packets Received":     { "type": "long" },
        "Elapsed Time in seconds": { "type": "integer" },
        "Action":               { "type": "keyword" },
        "Application":          { "type": "keyword" },
        "Rule Name":            { "type": "keyword" },
        "Source Zone":          { "type": "keyword" },
        "Destination Zone":     { "type": "keyword" },
        "IP Protocol":          { "type": "keyword" },
        "Type":                 { "type": "keyword" },
        "Device Name":          { "type": "keyword" },
        "Session End Reason":   { "type": "keyword" },
        "forwarder_enrichment": {
          "properties": {
            "geoip": {
              "properties": {
                "src": {
                  "properties": {
                    "country_code":  { "type": "keyword" },
                    "country_name":  { "type": "keyword" },
                    "city":          { "type": "keyword" },
                    "location":      { "type": "geo_point" }
                  }
                },
                "dst": {
                  "properties": {
                    "country_code":  { "type": "keyword" },
                    "country_name":  { "type": "keyword" },
                    "city":          { "type": "keyword" },
                    "location":      { "type": "geo_point" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}' > /dev/null
    log "Index template created."
}

# ---------------------------------------------------------------------------
create_data_view() {
    log "Creating Kibana data view..."
    curl -sf -X POST --cacert "$CACERT" -u "$AUTH" \
        "${KIBANA_URL}/api/data_views/data_view" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
  \"data_view\": {
    \"id\": \"${DV_ID}\",
    \"title\": \"prodepa-logs-*\",
    \"timeFieldName\": \"@timestamp\"
  }
}" > /dev/null || log "Data view may already exist — continuing."
    log "Data view ready."
}

# ---------------------------------------------------------------------------
import_saved_objects() {
    log "Importing Kibana dashboards and visualizations..."
    NDJSON_FILE=$(mktemp)

    # Each line is one saved object (strict NDJSON).
    # Visualization IDs are prefixed sc- to avoid collisions.
    cat > "$NDJSON_FILE" <<NDJSON
{"type":"lens","id":"sc-events-over-time","attributes":{"title":"Events Over Time","visualizationType":"lnsXY","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-ts":{"label":"@timestamp","dataType":"date","operationType":"date_histogram","sourceField":"@timestamp","isBucketed":true,"scale":"interval","params":{"interval":"auto","includeEmptyRows":true,"dropPartials":false}},"col-count":{"label":"Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-ts","col-count"],"incompleteColumns":{}}}}},"visualization":{"legend":{"isVisible":true,"position":"right"},"valueLabels":"hide","fittingFunction":"None","axisTitlesVisibilitySettings":{"x":false,"yLeft":false,"yRight":false},"tickLabelsVisibilitySettings":{"x":true,"yLeft":true,"yRight":true},"gridlinesVisibilitySettings":{"x":true,"yLeft":true,"yRight":true},"preferredSeriesType":"bar_stacked","layers":[{"layerId":"l1","accessors":["col-count"],"position":"top","seriesType":"bar_stacked","showGridlines":false,"layerType":"data","xAccessor":"col-ts"}]},"query":{"query":"","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-action-distribution","attributes":{"title":"Action Distribution","visualizationType":"lnsPie","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-action":{"label":"Action","dataType":"string","operationType":"terms","sourceField":"Action","isBucketed":true,"scale":"ordinal","params":{"size":10,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":true,"missingBucket":false}},"col-count":{"label":"Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-action","col-count"],"incompleteColumns":{}}}}},"visualization":{"shape":"pie","layers":[{"layerId":"l1","primaryGroups":["col-action"],"metrics":["col-count"],"layerType":"data","numberDisplay":"percent","categoryDisplay":"default","legendDisplay":"default","nestedLegend":false}]},"query":{"query":"","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-top-source-ips","attributes":{"title":"Top Source IPs","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-src":{"label":"Source address","dataType":"string","operationType":"terms","sourceField":"Source address","isBucketed":true,"scale":"ordinal","params":{"size":15,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Connections","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-src","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-src","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-top-applications","attributes":{"title":"Top Applications","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-app":{"label":"Application","dataType":"string","operationType":"terms","sourceField":"Application","isBucketed":true,"scale":"ordinal","params":{"size":15,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-app","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-app","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-top-dest-ports","attributes":{"title":"Top Destination Ports","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-port":{"label":"Destination Port","dataType":"number","operationType":"terms","sourceField":"Destination Port","isBucketed":true,"scale":"ordinal","params":{"size":15,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-port","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-port","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-threat-intel-hits","attributes":{"title":"Threat Intel Hits Over Time","visualizationType":"lnsXY","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-ts":{"label":"@timestamp","dataType":"date","operationType":"date_histogram","sourceField":"@timestamp","isBucketed":true,"scale":"interval","params":{"interval":"auto","includeEmptyRows":false,"dropPartials":false}},"col-count":{"label":"Threat Intel Hits","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-ts","col-count"],"incompleteColumns":{}}}}},"visualization":{"legend":{"isVisible":true,"position":"right"},"valueLabels":"hide","fittingFunction":"None","preferredSeriesType":"bar_stacked","layers":[{"layerId":"l1","accessors":["col-count"],"position":"top","seriesType":"bar_stacked","showGridlines":false,"layerType":"data","xAccessor":"col-ts"}]},"query":{"query":"forwarder_enrichment.ioc_matches:*","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-top-blocked-ips","attributes":{"title":"Top Blocklisted Source IPs","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-src":{"label":"Source address","dataType":"string","operationType":"terms","sourceField":"Source address","isBucketed":true,"scale":"ordinal","params":{"size":20,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Hit Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-src","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-src","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"forwarder_enrichment.ioc_matches:*","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-behavioral-anomalies","attributes":{"title":"Behavioral Anomalies Over Time","visualizationType":"lnsXY","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-ts":{"label":"@timestamp","dataType":"date","operationType":"date_histogram","sourceField":"@timestamp","isBucketed":true,"scale":"interval","params":{"interval":"auto","includeEmptyRows":false,"dropPartials":false}},"col-count":{"label":"Anomalies","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-ts","col-count"],"incompleteColumns":{}}}}},"visualization":{"legend":{"isVisible":true,"position":"right"},"valueLabels":"hide","fittingFunction":"None","preferredSeriesType":"bar_stacked","layers":[{"layerId":"l1","accessors":["col-count"],"position":"top","seriesType":"bar_stacked","showGridlines":false,"layerType":"data","xAccessor":"col-ts"}]},"query":{"query":"forwarder_enrichment.behavioral_anomalies:*","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-correlation-rules","attributes":{"title":"Correlation Rules Fired","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-rule":{"label":"Rule","dataType":"string","operationType":"terms","sourceField":"forwarder_enrichment.threat_hunting.correlation_rules.rule","isBucketed":true,"scale":"ordinal","params":{"size":20,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Count","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-rule","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-rule","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"forwarder_enrichment.threat_hunting.correlation_rules:*","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"lens","id":"sc-src-country-map","attributes":{"title":"Source Country Distribution","visualizationType":"lnsDatatable","state":{"datasourceStates":{"formBased":{"layers":{"l1":{"indexPatternId":"prodepa-data-view","columns":{"col-country":{"label":"Source Country","dataType":"string","operationType":"terms","sourceField":"forwarder_enrichment.geoip.src.country_name","isBucketed":true,"scale":"ordinal","params":{"size":20,"orderBy":{"type":"column","columnId":"col-count"},"orderDirection":"desc","otherBucket":false,"missingBucket":false}},"col-count":{"label":"Connections","dataType":"number","operationType":"count","isBucketed":false,"scale":"ratio","sourceField":"___records___","params":{}}},"columnOrder":["col-country","col-count"],"incompleteColumns":{}}}}},"visualization":{"columns":[{"columnId":"col-country","isTransposed":false},{"columnId":"col-count","isTransposed":false}],"layerId":"l1","layerType":"data"},"query":{"query":"forwarder_enrichment.geoip.src.country_name:*","language":"kuery"},"filters":[]}},"references":[{"type":"index-pattern","id":"prodepa-data-view","name":"indexpattern-datasource-layer-l1"}]}
{"type":"dashboard","id":"sc-dashboard-overview","attributes":{"title":"SporeCast — Security Overview","description":"Traffic volume, top talkers, action breakdown","panelsJSON":"[{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":16,\"i\":\"p1\"},\"panelIndex\":\"p1\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p1\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":16,\"w\":16,\"h\":14,\"i\":\"p2\"},\"panelIndex\":\"p2\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p2\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":16,\"y\":16,\"w\":16,\"h\":14,\"i\":\"p3\"},\"panelIndex\":\"p3\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p3\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":32,\"y\":16,\"w\":16,\"h\":14,\"i\":\"p4\"},\"panelIndex\":\"p4\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p4\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":30,\"w\":24,\"h\":14,\"i\":\"p5\"},\"panelIndex\":\"p5\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p5\"}]","optionsJSON":"{\"useMargins\":true,\"syncColors\":false,\"syncCursor\":true,\"syncTooltips\":false,\"hidePanelTitles\":false}","timeRestore":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"panel-p1","type":"lens","id":"sc-events-over-time"},{"name":"panel-p2","type":"lens","id":"sc-action-distribution"},{"name":"panel-p3","type":"lens","id":"sc-top-source-ips"},{"name":"panel-p4","type":"lens","id":"sc-top-applications"},{"name":"panel-p5","type":"lens","id":"sc-top-dest-ports"}]}
{"type":"dashboard","id":"sc-dashboard-threat-intel","attributes":{"title":"SporeCast — Threat Intelligence","description":"IOC matches, blocked IPs, correlation rules, behavioral anomalies, GeoIP","panelsJSON":"[{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":15,\"i\":\"p1\"},\"panelIndex\":\"p1\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p1\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":15,\"w\":24,\"h\":14,\"i\":\"p2\"},\"panelIndex\":\"p2\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p2\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":24,\"y\":15,\"w\":24,\"h\":14,\"i\":\"p3\"},\"panelIndex\":\"p3\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p3\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":29,\"w\":48,\"h\":15,\"i\":\"p4\"},\"panelIndex\":\"p4\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p4\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":0,\"y\":44,\"w\":24,\"h\":14,\"i\":\"p5\"},\"panelIndex\":\"p5\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p5\"},{\"version\":\"8.0.0\",\"type\":\"lens\",\"gridData\":{\"x\":24,\"y\":44,\"w\":24,\"h\":14,\"i\":\"p6\"},\"panelIndex\":\"p6\",\"embeddableConfig\":{\"enhancements\":{}},\"panelRefName\":\"panel-p6\"}]","optionsJSON":"{\"useMargins\":true,\"syncColors\":false,\"syncCursor\":true,\"syncTooltips\":false,\"hidePanelTitles\":false}","timeRestore":false,"kibanaSavedObjectMeta":{"searchSourceJSON":"{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"}},"references":[{"name":"panel-p1","type":"lens","id":"sc-threat-intel-hits"},{"name":"panel-p2","type":"lens","id":"sc-top-blocked-ips"},{"name":"panel-p3","type":"lens","id":"sc-correlation-rules"},{"name":"panel-p4","type":"lens","id":"sc-behavioral-anomalies"},{"name":"panel-p5","type":"lens","id":"sc-src-country-map"},{"name":"panel-p6","type":"lens","id":"sc-top-applications"}]}
NDJSON

    curl -sf -X POST --cacert "$CACERT" -u "$AUTH" \
        "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
        -H "kbn-xsrf: true" \
        -F "file=@${NDJSON_FILE}" > /dev/null

    rm -f "$NDJSON_FILE"
    log "Dashboards and visualizations imported."
}

# ---------------------------------------------------------------------------
create_alert_rules() {
    log "Creating alerting rules..."

    # Threat Intel Hit — fires when any log has IOC matches
    curl -sf -X POST --cacert "$CACERT" -u "$AUTH" \
        "${KIBANA_URL}/api/alerting/rule" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
  "name": "SporeCast — Threat Intel Hit",
  "tags": ["sporecast", "threat-intel"],
  "rule_type_id": ".es-query",
  "consumer": "stackAlerts",
  "schedule": {"interval": "1m"},
  "params": {
    "index": ["prodepa-logs-*"],
    "timeField": "@timestamp",
    "esQuery": "{\"query\":{\"exists\":{\"field\":\"forwarder_enrichment.ioc_matches\"}}}",
    "size": 100,
    "thresholdComparator": ">",
    "threshold": [0],
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "excludeHitsFromPreviousRun": true
  },
  "actions": [],
  "notify_when": "onActiveAlert"
}' > /dev/null || log "Warning: threat intel rule creation failed (may already exist)."

    # Behavioral Anomaly — fires when behavioral analysis flags a source
    curl -sf -X POST --cacert "$CACERT" -u "$AUTH" \
        "${KIBANA_URL}/api/alerting/rule" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
  "name": "SporeCast — Behavioral Anomaly",
  "tags": ["sporecast", "behavioral"],
  "rule_type_id": ".es-query",
  "consumer": "stackAlerts",
  "schedule": {"interval": "1m"},
  "params": {
    "index": ["prodepa-logs-*"],
    "timeField": "@timestamp",
    "esQuery": "{\"query\":{\"exists\":{\"field\":\"forwarder_enrichment.behavioral_anomalies\"}}}",
    "size": 100,
    "thresholdComparator": ">",
    "threshold": [0],
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "excludeHitsFromPreviousRun": true
  },
  "actions": [],
  "notify_when": "onActiveAlert"
}' > /dev/null || log "Warning: behavioral anomaly rule creation failed (may already exist)."

    # Correlation Rule Fired — brute force, lateral movement, C2, etc.
    curl -sf -X POST --cacert "$CACERT" -u "$AUTH" \
        "${KIBANA_URL}/api/alerting/rule" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
  "name": "SporeCast — Correlation Rule Fired",
  "tags": ["sporecast", "correlation"],
  "rule_type_id": ".es-query",
  "consumer": "stackAlerts",
  "schedule": {"interval": "2m"},
  "params": {
    "index": ["prodepa-logs-*"],
    "timeField": "@timestamp",
    "esQuery": "{\"query\":{\"exists\":{\"field\":\"forwarder_enrichment.threat_hunting.correlation_rules\"}}}",
    "size": 100,
    "thresholdComparator": ">",
    "threshold": [0],
    "timeWindowSize": 5,
    "timeWindowUnit": "m",
    "excludeHitsFromPreviousRun": true
  },
  "actions": [],
  "notify_when": "onActiveAlert"
}' > /dev/null || log "Warning: correlation rule creation failed (may already exist)."

    log "Alerting rules created. Configure notification connectors in Kibana Stack Management > Rules."
}

# ---------------------------------------------------------------------------
wait_for_kibana
create_index_template
create_data_view
import_saved_objects
create_alert_rules

log "============================================================"
log "Provisioning complete."
log "Dashboards available in Kibana > Analytics > Dashboards:"
log "  - SporeCast — Security Overview"
log "  - SporeCast — Threat Intelligence"
log "Alerting rules active in Kibana > Stack Management > Rules."
log "Add notification connectors (Slack/email/webhook) as needed."
log "============================================================"
