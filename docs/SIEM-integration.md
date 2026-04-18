# GhostRing — SIEM integration

Drop-in configs for the three most common log pipelines.  Every
example reads from `ghostring-agent --json --monitor` (one JSON line
per alert) and ships the stream without modification.

## Event schema

Each alert is one JSON object on one line:

```json
{"ts":"2026-04-18T01:03:11Z","host":"kz-sec-01","event":"alert","cpu":3,"type":"ransomware_canary","type_id":6,"info":"0x7ffee0001000","kernel_ts_ns":123456789012345}
```

Fields:

| Field           | Type   | Meaning                                              |
|-----------------|--------|------------------------------------------------------|
| `ts`            | string | ISO-8601 UTC timestamp the agent received the alert  |
| `host`          | string | `uname -n` of the endpoint                           |
| `event`         | string | Always `alert` for this stream, `status` for probes  |
| `cpu`           | int    | Logical CPU that raised the event                    |
| `type`          | string | Symbolic alert name (see `docs/DETECTORS.md`)        |
| `type_id`       | int    | Numeric alert type (matches kernel ring buffer)      |
| `info`          | string | Per-detector hex payload (GPA, MSR value, offset…)   |
| `kernel_ts_ns`  | int    | `ktime_get_ns()` at the moment the exit was taken    |

## systemd-journald

The simplest deployment — pipe the agent into `logger` and let
journald rotate / forward like any other service.

Save as `/etc/systemd/system/ghostring-agent.service`:

```ini
[Unit]
Description=GhostRing Agent
After=network.target
# Do NOT require /dev/ghostring at unit start — agent waits and retries.

[Service]
Type=simple
ExecStart=/usr/local/bin/ghostring-agent --json --monitor
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ghostring
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable: `systemctl enable --now ghostring-agent`.

Query: `journalctl -u ghostring-agent -f --output=json`.

## Filebeat → Elasticsearch / OpenSearch

`/etc/filebeat/inputs.d/ghostring.yml`:

```yaml
- type: unix
  paths:
    - /var/run/ghostring-agent.sock
  fields:
    product: ghostring
    version: "0.1.0"
  fields_under_root: true
  processors:
    - decode_json_fields:
        fields: ["message"]
        target: ""
        overwrite_keys: true
```

Or, simpler, pipe the agent directly:

`/etc/filebeat/filebeat.yml`:

```yaml
filebeat.inputs:
  - type: stdin
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://siem.internal:9200"]
  index: "ghostring-%{+yyyy.MM.dd}"

setup.template.name: "ghostring"
setup.template.pattern: "ghostring-*"
```

Run: `ghostring-agent --json --monitor | filebeat -e`.

## Splunk HEC

`/etc/splunkforwarder/local/inputs.conf`:

```ini
[script://./bin/ghostring-agent-wrapper.sh]
interval = -1
index = ghostring
sourcetype = ghostring:json
source = ghostring-agent
```

Wrapper (`bin/ghostring-agent-wrapper.sh`):

```bash
#!/usr/bin/env bash
exec /usr/local/bin/ghostring-agent --json --monitor
```

Or direct HEC without the forwarder:

```bash
ghostring-agent --json --monitor | \
  while IFS= read -r line; do
    curl -sS -H "Authorization: Splunk $HEC_TOKEN" \
         -d "{\"event\": $line, \"sourcetype\": \"ghostring:json\"}" \
         https://splunk:8088/services/collector/event
  done
```

## Kafka

For very high-volume deployments, send alerts into Kafka via
`kcat` (formerly `kafkacat`):

```bash
ghostring-agent --json --monitor | \
  kcat -P -b kafka.internal:9092 -t ghostring.alerts
```

Consumer side can be any Kafka-compatible analytics pipeline.

## Sizing

- Every exit the hypervisor takes that escalates to the alert ring
  emits exactly one 24-byte kernel record.
- The agent decodes to roughly 250-300 bytes of JSON.
- Expected steady-state volume on a quiet endpoint: **< 10 alerts /
  minute**.  Ransomware or DKOM events spike briefly to thousands
  per second and then subside.
- Filebeat / rsyslog at default settings keeps up without tuning.

## Example detection scenarios for dashboards

| Dashboard panel | SIEM query (pseudocode)                                  |
|-----------------|----------------------------------------------------------|
| Rootkit attempts | `type IN ("idt_hook", "ssdt_hook", "msr_write")`        |
| Kernel integrity | `type = "integrity_crc_mismatch"`                       |
| Ransomware      | `type = "ransomware_canary"` (single hit = incident)    |
| Privilege esc   | `type IN ("cr_write", "rop_violation", "code_inject")`  |
| Hidden proc     | `type = "dkom_hidden_cr3"`                              |

Each panel maps 1:1 to a MITRE ATT&CK tactic — the full map is in
`docs/DETECTORS.md`.
