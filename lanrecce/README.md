# lanrecce

Local network assessment, the internal-network sibling of
[recce](../recce): the same stage pipeline, scope gate and finding shape. It runs
as a **web console** (Docker Compose) or a **CLI**, drives nmap, naabu, httpx and
nuclei, and exports straight into **Dossier**. No Postgres or Redis: each run is a
folder under `runs/`.

```
discovery ─> ports ─> services ─> web ─> nuclei ─> checks ─> intel ─> report
 nmap -sn    naabu    nmap -sV    httpx   web pass  SMB/TLS/  KEV +    html, json, csv,
 (ARP when            + safe NSE          + network cleartext EPSS     Dossier (.nessus
  privileged)         + vulners           pass      /no-auth  tiering  + nmap xml)
```

## Quick start: Docker Compose + web console

```bash
cp .env.example .env              # defaults are fine for localhost use
docker compose up -d --build      # first build takes a few minutes
```

Open **http://localhost:8088**, then:

1. **New scan**: pick targets (your subnets are offered as one-click chips), an
   exclude list and a profile, then start it.
2. **Watch it run**: a live stage strip and console, with findings appearing as nuclei finds them.
   **Stop** saves state; **Resume** carries on later.
3. **Review**: filterable findings with evidence, a host inventory and the full HTML report.
4. **Export → Dossier**: download one zip, then drop both files on Dossier's Import page.

Compose settings (`.env`):

| variable | default | |
|---|---|---|
| `LANRECCE_BIND` / `LANRECCE_PORT` | `127.0.0.1` / `8088` | where the console listens (host networking) |
| `LANRECCE_TOKEN` | empty | access token. **Required** for any non-loopback bind |
| `LANRECCE_ALLOWED_HOSTS` | empty | extra Host names accepted when no token is set |
| `LANRECCE_ALLOW_PUBLIC` | `0` | `1` lets the console scan non-private ranges |
| `LANRECCE_DOSSIER_URL` | `http://localhost:8080` | "Open Dossier" button |
| `LANRECCE_UID` / `LANRECCE_GID` | `1000` | who owns `./runs` |

The container uses `network_mode: host` (it has to be on your LAN) and
`NET_RAW` + `NET_ADMIN` (ARP discovery, SYN scans, OS detection, UDP). It doesn't need
`--privileged`. **Linux only**: Docker Desktop on macOS/Windows runs containers in
a VM that can't see your LAN at layer 2.

```bash
docker compose logs -f                        # server log
docker compose run --rm update-templates      # refresh nuclei templates
docker compose run --rm lanrecce scan 10.0.0.0/24 --yes   # CLI inside the stack
docker compose down                           # stop (runs/ stays)
```

### Remote access

The console can start network scans, so it's locked down by default:

- It listens on 127.0.0.1. Any other bind is refused unless `LANRECCE_TOKEN` is set,
  which adds a sign-in page (or `Authorization: Bearer <token>` for the API).
- Requests that change something need an `X-Lanrecce: 1` header, which other
  websites can't send (cross-site request forgery protection).
- Without a token, Host headers are allow-listed, which blocks DNS rebinding.
- Reports are served with CSP `sandbox`. Text pulled from scanned devices is never
  rendered as HTML.
- Scope is validated on the server with the same rules as the CLI: private
  ranges only, at most 65,536 addresses, one scan at a time.

For access from another machine, prefer an SSH tunnel (`ssh -L 8088:127.0.0.1:8088 box`).
Otherwise set `LANRECCE_BIND=0.0.0.0` plus a long `LANRECCE_TOKEN`, ideally behind
a TLS reverse proxy.

## Exporting to Dossier

Every run writes two files that Dossier's **Import** page reads (drop them
together, or use the console's *Export → Download both (.zip)* and unzip):

| file | Dossier importer | brings in |
|---|---|---|
| `dossier-findings.nessus` | Nessus | findings: Critical to Info, CVSS, CWE, CVEs + links as references, description, remediation, and **evidence** (matched URL/port, template, KEV/EPSS/priority, request/response) |
| `dossier-hosts.xml` | Nmap XML | every live host and open port, with product/version and OS |

Both were verified against your deployed Dossier's import code and by an
actual import. Dossier merges hosts by IP and skips findings it already has
(same title, severity and host), so re-importing a run is safe. Where one host
has the same issue on two ports, the port is added to the title so neither is
dropped. `findings.nuclei.jsonl` is still written for recce, but Dossier's
nuclei importer keeps no evidence, so use the `.nessus` file.

## Native install (CLI, no Docker)

Already set up on this machine (`./lanrecce.sh doctor`). On a new box:

```bash
./install.sh            # nmap, vulners.nse, naabu, httpx, nuclei + templates
./install.sh --setcap   # optional: raw scans without sudo (single-user boxes only)
```

## Docker without Compose (CLI)

The same image, one-shot CLI runs.
Linux hosts only: the container must share the host's network to see the LAN.

```bash
./docker-run.sh build                     # build the image (a few minutes)
./docker-run.sh doctor
./docker-run.sh scan --auto               # results in ./runs, owned by you
./docker-run.sh scan 192.168.1.0/24 -x 192.168.1.1 -p quick
./docker-run.sh update-templates          # refresh nuclei templates
```

`docker-run.sh` adds the flags that matter:

- `--network host`: on Docker's default bridge network the container can't reach your LAN.
- `--cap-add NET_RAW --cap-add NET_ADMIN`: ARP discovery, SYN scans, OS detection and UDP.
  No `--privileged` needed.
- `LANRECCE_CHOWN`: your uid:gid, so `./runs` isn't root-owned.
- volumes `lanrecce-cache` (KEV/EPSS cache) and `lanrecce-templates` (nuclei templates; the
  first run copies the image's templates into the volume, and `update-templates` refreshes them).

Plain docker, without the wrapper:

```bash
docker build -t lanrecce .
docker run --rm -it --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e LANRECCE_CHOWN="$(id -u):$(id -g)" -v "$PWD/runs:/data/runs" lanrecce scan --auto
```

On Docker Desktop (macOS/Windows), containers run inside a VM, so ARP discovery can't see
your LAN. Use the native install there.

## Use

```bash
./lanrecce.sh subnets                          # what --auto would scan
sudo ./lanrecce.sh scan --auto                 # every LAN you're attached to
sudo ./lanrecce.sh scan 192.168.1.0/24 -x 192.168.1.1 -p quick
sudo ./lanrecce.sh scan @targets.txt -p full --name office-q4
./lanrecce.sh scan --resume runs/office-q4     # continue after Ctrl-C
./lanrecce.sh scan 10.0.0.0/24 --baseline runs/office-q3   # marks new / fixed
./lanrecce.sh report runs/office-q4 --baseline runs/office-q3
sudo ./lanrecce.sh serve                       # web console on http://localhost:8088
```

Run it with **sudo**. As root, nmap does ARP discovery (it finds devices that
drop all TCP: printers, phones, IoT), SYN scans, OS detection and UDP.
Without root, discovery falls back to TCP connect pings and misses quiet hosts.
Under sudo, httpx and nuclei drop back to your user, so templates and caches
stay in your home and the run directory is chowned back to you.

### Profiles

| profile    | TCP ports                         | nuclei severities | extra |
|------------|-----------------------------------|-------------------|-------|
| `quick`    | nmap top 100 + ~75 LAN-critical   | medium+           | |
| `standard` | nmap top 1000 + LAN-critical      | low+              | default |
| `full`     | all 65535                         | all incl. info    | UDP top 25, TLS cipher audit, x11/snmp |

"LAN-critical" ports are always included: Redis, Mongo, Elastic, Memcached,
Docker API, kubelet/etcd, IPMI, WinRM, Modbus/BACnet/EtherNet-IP and so on.

### Safety defaults

- **Scope is enforced in code and fails closed.** Every target and every
  result (including httpx/nuclei output) is checked against the CIDRs.
  Public ranges are refused unless you pass `--allow-public`.
- More than 1024 addresses asks for confirmation (or needs `--yes`).
- nuclei `dos`, `fuzz` and `intrusive` templates never run. **Default-login
  templates are off** (they can lock accounts); enable them with
  `--default-logins`.
- **Interactsh is off** (`-ni`), so nothing calls out to public oast.* servers
  from inside the network. Enable it with `--interactsh`.
- NSE scripts are limited to discovery/safe ones.

## Output (`runs/<name>/`)

| file | |
|------|-|
| `report.html` | self-contained report: severity summary, filterable findings with evidence, host inventory |
| `findings.json` / `findings.csv` | all findings, recce-shaped |
| `dossier-findings.nessus` + `dossier-hosts.xml` | Dossier import pair (see above) |
| `findings.nuclei.jsonl` | nuclei-format export (recce-compatible) |
| `console.log` | scan output (web-launched runs) |
| `hosts.json` | inventory: MAC/vendor, OS, ports, versions, NSE output, web apps |
| `state.json` | resumable run state |
| `raw/`, `tools.log` | every tool's raw output and stderr |

## What it finds

- **nuclei web pass** (`-pt http`) on every live URL httpx finds.
- **nuclei network pass** (`-pt tcp,javascript,ssl`) on every open `ip:port`.
  recce doesn't run this one, and on a LAN it matters most: Redis, Mongo, SMB,
  SSH, RDP, MQTT, FTP and other misconfigurations and CVEs.
- **Built-in checks** from nmap/NSE: SMB signing not required, SMBv1, SMB
  guest, anonymous FTP, unauthenticated Redis/Mongo/VNC, open X11, RDP without
  NLA, SSHv1, NFS exports, SNMP `public`, IPMI, exposed Docker API, kubelet and
  memcached, cleartext Telnet/FTP/r-services, deprecated TLS/weak ciphers, and
  expired/self-signed certificates. When nuclei reports the same issue, the
  check is dropped in favour of nuclei's evidence.
- **vulners** version-to-CVE matching. Below `--min-cvss` (7.0 by default),
  CVEs are rolled into one low finding per service unless a public exploit
  exists. These are version matches, so verify them: distros backport fixes.
- **CVE intel**: CISA KEV and FIRST EPSS, sorted into fire/smoke/ice tiers
  (cached in `~/.cache/lanrecce`; skip with `--offline`).

## Performance

The nuclei network pass is the slow stage: about 5 minutes even for a couple of hosts,
because many TCP/JavaScript templates wait for timeouts. nuclei runs hosts in parallel,
so a /24 doesn't take 254 times as long. For a quick look, use
`-p quick --severity critical,high`.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```
