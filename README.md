# mithra

Mithra is a network probing tool that samples IP addresses from CIDR ranges and tests
their connectivity and HTTP behavior.

It is designed for large-scale IP range validation, service reachability checks,
and automated probing of network endpoints.

---

## Features

- Random sampling of IPs from CIDR ranges.
- Minimum and maximum sample limits per CIDR.
- Probabilistic sampling control.
- TLS connectivity checks with optional SNI.
- Optional HTTP status code validation.
- Per-IP execution timeout.
- Configurable via CLI flags or config file.

---

## Installation

```bash
go install github.com/fmotalleb/mithra@latest
````

Or build locally:

```bash
git clone https://github.com/fmotalleb/mithra.git
cd mithra
go build
```

---

## Usage

```bash
mithra [flags]
```

---

## Flags

| Flag            | Default           | Description                                       |
| --------------- | ----------------- | ------------------------------------------------- |
| `-v, --verbose` | false             | Enable debug logging                              |
| `-c, --config`  | ""                | Config file path (default: read from stdin)       |
| `--cidr`        | Cloudflare ranges | CIDRs to test against                             |
| `-t, --timeout` | 1s                | Timeout per IP                                    |
| `--sni`         | ""                | SNI hostname                                      |
| `--port`        | 443               | Port to test                                      |
| `--status`      | 0                 | Expected HTTP status code (0 disables HTTP check) |
| `--min-count`   | 1                 | Minimum IP samples per CIDR                       |
| `--max-count`   | 30                | Maximum IP samples per CIDR                       |
| `--chance`      | 0.05              | Probability of picking each IP                    |
| `-o, --output`  | ""                | Write results to the output file (only success)   |

Multiple CIDRs can be passed:

```bash
mithra --cidr 1.1.1.0/24 --cidr 8.8.8.0/24
```

---

## Configuration

Config structure:

```yaml
cidr:
  - 1.1.1.0/24
  - 8.8.8.0/24

sni: example.com
timeout: 1
port: 443
status_code: 200

sample_min: 5
sample_max: 50
sample_chance: 0.1
```

Fields:

| Field           | Description                    |
| --------------- | ------------------------------ |
| `cidr`          | CIDR ranges to scan            |
| `sni`           | TLS SNI hostname               |
| `timeout`       | Timeout per IP                 |
| `port`          | Port to connect                |
| `status_code`   | Expected HTTP status           |
| `sample_min`    | Minimum samples per CIDR       |
| `sample_max`    | Maximum samples per CIDR       |
| `sample_chance` | Probability of selecting an IP |

---

## Examples

Probe Cloudflare IPs with HTTP validation:

```bash
mithra --sni example.com --status 200
```

Probe a custom CIDR with higher sampling:

```bash
mithra --cidr 10.0.0.0/16 --min-count 20 --max-count 100 --chance 0.2
```

---

## Output

* Successful probes are logged at `info` level.
* Failed probes are logged at `debug` level.
* Results include IP, status, and execution metadata.
