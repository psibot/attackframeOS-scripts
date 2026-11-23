# lanrecce: local network assessment in a container.
#
#   docker compose up -d --build          # web console on http://localhost:8088
#   ./docker-run.sh scan --auto           # or the CLI
#
# --network host is REQUIRED: on Docker's bridge network the container can't
# see your LAN (no ARP, wrong subnets). Linux hosts only; Docker Desktop on
# Mac/Windows runs containers inside a VM and can't reach the LAN at layer 2.
# Or use ./docker-run.sh, which sets all of this up.

# ---- stage 1: ProjectDiscovery tools (prebuilt release binaries via pdtm) ----
# Built on bookworm so naabu's dynamic libpcap link matches the runtime image.
FROM golang:1.25-bookworm AS tools
ENV GOTOOLCHAIN=auto
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN pdtm -no-color -disable-update-check -install naabu,httpx,nuclei \
 && test -x /root/.pdtm/go/bin/naabu \
 && test -x /root/.pdtm/go/bin/httpx \
 && test -x /root/.pdtm/go/bin/nuclei

# ---- stage 2: runtime --------------------------------------------------------
FROM debian:bookworm-slim

# nmap        discovery / ports / services / NSE
# libpcap0.8  naabu runtime
# iproute2    `ip -j addr` for --auto subnet detection
# libcap2-bin getcap (doctor)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 nmap libpcap0.8 iproute2 libcap2-bin ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tools /root/.pdtm/go/bin/naabu /root/.pdtm/go/bin/httpx /root/.pdtm/go/bin/nuclei /usr/local/bin/
RUN naabu -version && httpx -version && nuclei -version

# vulners NSE (version -> CVE matching). Fail the build if it doesn't load.
RUN curl -fsSL https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse \
      -o /usr/share/nmap/scripts/vulners.nse \
 && nmap --script-updatedb >/dev/null \
 && nmap --script-help vulners | grep -q vulners

# Bake nuclei templates into the image so scans work offline / air-gapped.
# Rebuild the image (or run `lanrecce-update`) to refresh them.
RUN nuclei -update-templates \
 && test -d /root/nuclei-templates/network
RUN printf '#!/bin/sh\nexec nuclei -update-templates\n' > /usr/local/bin/lanrecce-update \
 && chmod +x /usr/local/bin/lanrecce-update

COPY lanrecce /opt/lanrecce/lanrecce
COPY tests /opt/lanrecce/tests
COPY README.md /opt/lanrecce/
RUN cd /opt/lanrecce && python3 -m unittest discover -s tests -t . 2>&1 | tail -1

ENV PYTHONPATH=/opt/lanrecce PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /data
ENV LANRECCE_RUNS=/data/runs
EXPOSE 8088
ENTRYPOINT ["python3", "-m", "lanrecce"]
# default: the web console (docker compose). `docker run ... lanrecce scan ...` for CLI.
CMD ["serve"]
