#!/bin/bash

# Intro and User confirmation
echo ""
echo "================================================================="
echo "Unified Prometheus + SNMP Exporter Setup for CentOS 8.5+ Systems"
echo "================================================================="
echo ""
echo "This script will:"
echo " - Install needed modules and packages."
echo " - Install Docker and Docker compose v2 if needed."
echo " - Install Grafana (unless already running)."
echo " - Download a pinned default snmp.yml file."
echo " - Add embedded lean ServerTech PDU SNMP support."
echo " - Normalize the generated prometheus.yml for the single local SNMP Exporter."
echo " - Prompt user for full file path to prometheus.yml after generation."
echo " - Build a Docker container with Prometheus and SNMP Exporter."
echo ""
echo "IMPORTANT:"
echo " - Ensure you also have the repository hammerspace-grafana-dashboards from hammer-space cloned or on your CentOS environment."
echo "   (Needed for generation of prometheus.yml, has instructions for generation)"
echo " - You may run this script first to install Grafana, it will stop and prompt for the prometheus.yml file path after."
echo " - You will need to create a service account:"
echo "    - Administration > Users and Access > Service Accounts"
echo "    - Create the Service Account with role of admin."
echo ""
echo "If unsure, stop and consult setup documentation."
echo ""

while true; do
  read -p "Continue with setup? (y/n): " confirm
  if [[ $confirm =~ ^[Yy]$ || $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
    break
  elif [[ $confirm =~ ^[Nn]$ || $confirm =~ ^[Nn][Oo]$ ]]; then
    echo ""
    echo "Aborted."
    exit 1
  else
    echo "Please enter yes or no."
  fi
done


# centos_prom_snmp_duo.sh
# INTERNAL USE ONLY CUSTOMERS GET A DIFFERENT ONE.
# Set up Docker and runs a unified Prometheus + SNMP Exporter service together on CentOS 8.5+.
set -euo pipefail
SNMP_EXPORTER_VERSION="0.26.0"
SERVERTECH_SNMP_MODULE=$(cat <<'EOF'
auths:
  public_v2:
    community: public
    security_level: noAuthNoPriv
    auth_protocol: MD5
    priv_protocol: DES
    version: 2

modules:
  servertech_pdu: &servertech_pdu_base
    walk:
      - 1.3.6.1.4.1.13742.6.3.3.3.1.1
      - 1.3.6.1.4.1.13742.6.3.3.3.1.2
      - 1.3.6.1.4.1.13742.6.3.3.3.1.3
      - 1.3.6.1.4.1.13742.6.3.3.4.1.6
      - 1.3.6.1.4.1.13742.6.3.3.4.1.7
      - 1.3.6.1.4.1.13742.6.3.5.3.1.1
      - 1.3.6.1.4.1.13742.6.3.5.3.1.2
      - 1.3.6.1.4.1.13742.6.3.5.3.1.3
      - 1.3.6.1.4.1.13742.6.3.5.3.1.28
      - 1.3.6.1.4.1.13742.6.3.5.4.1.6
      - 1.3.6.1.4.1.13742.6.3.5.4.1.7
      - 1.3.6.1.4.1.13742.6.5.2.3.1.4
      - 1.3.6.1.4.1.13742.6.5.4.3.1.4
    metrics:
      - name: inletId
        oid: 1.3.6.1.4.1.13742.6.3.3.3.1.1
        type: gauge
        help: A unique value for each inlet - 1.3.6.1.4.1.13742.6.3.3.3.1.1
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
      - name: inletLabel
        oid: 1.3.6.1.4.1.13742.6.3.3.3.1.2
        type: DisplayString
        help: The label on the PDU identifying the inlet. - 1.3.6.1.4.1.13742.6.3.3.3.1.2
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
      - name: inletName
        oid: 1.3.6.1.4.1.13742.6.3.3.3.1.3
        type: DisplayString
        help: The user-defined name. - 1.3.6.1.4.1.13742.6.3.3.3.1.3
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
      - name: inletSensorUnits
        oid: 1.3.6.1.4.1.13742.6.3.3.4.1.6
        type: gauge
        help: The unit in which the sensor reading is reported - 1.3.6.1.4.1.13742.6.3.3.4.1.6
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
        enum_values:
          1: volt
          2: amp
          3: watt
      - name: inletSensorDecimalDigits
        oid: 1.3.6.1.4.1.13742.6.3.3.4.1.7
        type: gauge
        help: The number of digits displayed to the right of the decimal point - 1.3.6.1.4.1.13742.6.3.3.4.1.7
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
      - name: measurementsInletSensorValue
        oid: 1.3.6.1.4.1.13742.6.5.2.3.1.4
        type: gauge
        help: The sensor reading as an unsigned integer - 1.3.6.1.4.1.13742.6.5.2.3.1.4
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: inletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
      - name: outletId
        oid: 1.3.6.1.4.1.13742.6.3.5.3.1.1
        type: gauge
        help: A unique value for each outlet - 1.3.6.1.4.1.13742.6.3.5.3.1.1
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
      - name: outletLabel
        oid: 1.3.6.1.4.1.13742.6.3.5.3.1.2
        type: DisplayString
        help: The label on the PDU identifying the outlet. - 1.3.6.1.4.1.13742.6.3.5.3.1.2
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
      - name: outletName
        oid: 1.3.6.1.4.1.13742.6.3.5.3.1.3
        type: DisplayString
        help: The user-defined name. - 1.3.6.1.4.1.13742.6.3.5.3.1.3
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
      - name: outletSwitchable
        oid: 1.3.6.1.4.1.13742.6.3.5.3.1.28
        type: gauge
        help: Is this outlet switchable? - 1.3.6.1.4.1.13742.6.3.5.3.1.28
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
        enum_values:
          1: "true"
          2: "false"
      - name: outletSensorUnits
        oid: 1.3.6.1.4.1.13742.6.3.5.4.1.6
        type: gauge
        help: The unit in which the sensor reading is reported - 1.3.6.1.4.1.13742.6.3.5.4.1.6
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
              14: onOff
        enum_values:
          -1: none
          0: other
          1: volt
          2: amp
          3: watt
      - name: outletSensorDecimalDigits
        oid: 1.3.6.1.4.1.13742.6.3.5.4.1.7
        type: gauge
        help: The number of digits displayed to the right of the decimal point - 1.3.6.1.4.1.13742.6.3.5.4.1.7
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
              14: onOff
      - name: measurementsOutletSensorValue
        oid: 1.3.6.1.4.1.13742.6.5.4.3.1.4
        type: gauge
        help: The sensor reading as an unsigned integer - 1.3.6.1.4.1.13742.6.5.4.3.1.4
        indexes:
          - labelname: pduId
            type: gauge
          - labelname: outletId
            type: gauge
          - labelname: sensorType
            type: gauge
            enum_values:
              1: rmsCurrent
              4: rmsVoltage
              5: activePower
              14: onOff
EOF
)
echo ""
echo "Starting Prometheus + SNMP Exporter Duo Setup..."
if [[ $EUID -ne 0 ]]; then
  echo "This script has to run as root. Exiting."
  exit 1
fi

# Checks for Missing Python packages/modules.
echo ""
echo "Checking for required Python packages..."
MISSING=false
# Check PyYAML
if python3 -c "import yaml; v=yaml.__version__.split('.'); exit(0) if int(v[0]) > 5 or (int(v[0]) == 5 and int(v[1]) >= 1) else exit(1)" 2>/dev/null; then
  echo "PyYAML version is compatible"
else
  echo "PyYAML is missing or outdated"
  MISSING=true
fi
# Check requests
if python3 -c "import requests" 2>/dev/null; then
  echo "requests module is present."
else
  echo "requests module is missing."
  MISSING=true
fi
# Check urllib3
if python3 -c "import urllib3" 2>/dev/null; then
  echo "urllib3 module is present."
else
  echo "urllib3 module is missing."
  MISSING=true
fi

# Prompt user to install missing packages or modules.
if [ "$MISSING" = true ]; then
  echo ""
  while true; do
    read -p "One or more required Python modules are missing or outdated. Install required modules now? (y/n): " confirm
    if [[ "$confirm" =~ ^[Yy]$ || "$confirm" =~ ^[Yy][Ee][Ss]$ ]]; then
      echo ""
      echo "Installing required packages with pip3..."
      pip3 install --user --upgrade PyYAML requests urllib3
      echo ""
      sleep 1
      echo "Required Python packages are now installed."
      break
    elif [[ "$confirm" =~ ^[Nn]$ || "$confirm" =~ ^[Nn][Oo]$ ]]; then
      echo ""
      echo "Exiting setup. Required Python packages must be installed manually."
      exit 1
    else
      echo "Please enter yes or no."
    fi
  done
fi

# Checks for Docker
if ! command -v docker &> /dev/null; then
  echo "Docker not found. Installing..."
  dnf install -y dnf-plugins-core
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y docker-ce docker-ce-cli containerd.io
  systemctl enable docker
  systemctl start docker
  echo "Docker installed and started."
else
  echo "Docker is already installed."
fi

# Checks for Docker compose v2
if ! docker compose version &> /dev/null; then
  echo "Docker Compose v2 not found. Installing..."
  mkdir -p ~/.docker/cli-plugins
  curl -SL https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-linux-x86_64 \
    -o ~/.docker/cli-plugins/docker-compose
  chmod +x ~/.docker/cli-plugins/docker-compose
  echo "Docker Compose v2 installed."
else
  echo "Docker Compose v2 is already installed."
fi

# Checks for Grafana, Installs if not already.
if ! systemctl is-active --quiet grafana-server; then
  echo "Grafana not installed or running. Installing..."

  cat <<EOF > /etc/yum.repos.d/grafana.repo
[grafana]
name=Grafana OSS
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
EOF

  dnf install -y grafana
  systemctl daemon-reexec
  systemctl enable --now grafana-server
  echo ""
  echo "Grafana installed and running on port 3000 (default user/pass = admin/admin)."
  echo "NOTE: CentOS systems usually block ports by default."
else
  echo "Grafana is already installed and running."
fi

# Prompt user to open required ports.
echo ""
while true; do
  read -p "Would you like to open firewall ports for Grafana (3000), Prometheus (9090), and SNMP Exporter (9116)? (y/n): " confirm
  if [[ $confirm =~ ^[Yy]$ || $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
    if command -v firewall-cmd &> /dev/null; then
      firewall-cmd --add-port=3000/tcp --permanent
      firewall-cmd --add-port=9090/tcp --permanent
      firewall-cmd --add-port=9116/tcp --permanent
      firewall-cmd --reload
      echo "Ports 3000, 9090, 9116 are now open."
    else
      echo "firewall-cmd was not found. Skipping port configuration."
      echo "Open ports 3000, 9090, and 9116 manually if a firewall is enabled."
    fi
    echo ""
    break
  elif [[ $confirm =~ ^[Nn]$ || $confirm =~ ^[Nn][Oo]$ ]]; then
    echo "Skipping port configuration, you may need to open ports manually."
    echo ""
    break
  else
    echo "Please enter yes or no."
  fi
done

# Set up project directory
echo "Setting up Directory Structure at /opt/monitoring-duo..."
mkdir -p /opt/monitoring-duo/config
mkdir -p /opt/monitoring-duo/snmp
echo "Directories created."

BASE_SNMP_TMP=$(mktemp)
CUSTOM_SNMP_TMP=$(mktemp)
PROM_YML_TMP=$(mktemp)
cleanup() {
  rm -f "$BASE_SNMP_TMP" "$CUSTOM_SNMP_TMP" "$PROM_YML_TMP"
}
trap cleanup EXIT

# Default official download for snmp.yml file from Prometheus Repo
echo "Fetching pinned snmp.yml from Prometheus GitHub..."
if ! curl -sSL "https://raw.githubusercontent.com/prometheus/snmp_exporter/v${SNMP_EXPORTER_VERSION}/snmp.yml" \
  -o "$BASE_SNMP_TMP"; then
  echo "Failed to download snmp.yml for snmp_exporter v${SNMP_EXPORTER_VERSION}."
  echo "Check network connectivity and try again."
  exit 1
fi
printf '%s\n' "$SERVERTECH_SNMP_MODULE" > "$CUSTOM_SNMP_TMP"

echo "Merging upstream snmp.yml with lean ServerTech module..."
if [[ -f /opt/monitoring-duo/snmp/snmp.yml ]]; then
  backup_path="/opt/monitoring-duo/snmp/snmp.yml.bak.$(date +%Y%m%d%H%M%S)"
  cp /opt/monitoring-duo/snmp/snmp.yml "$backup_path"
  echo "Backed up existing snmp.yml to $backup_path"
fi
python3 - "$BASE_SNMP_TMP" "$CUSTOM_SNMP_TMP" /opt/monitoring-duo/snmp/snmp.yml <<'PY'
from pathlib import Path
import sys

import yaml


def strip_datetime_pattern(node):
    if isinstance(node, dict):
        node.pop("datetime_pattern", None)
        for value in node.values():
            strip_datetime_pattern(value)
    elif isinstance(node, list):
        for item in node:
            strip_datetime_pattern(item)


def load_yaml(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


base_path, custom_path, output_path = sys.argv[1:4]
base_config = load_yaml(base_path)
custom_config = load_yaml(custom_path)

base_config.setdefault("auths", {}).update(custom_config.get("auths", {}))
base_config.setdefault("modules", {}).update(custom_config.get("modules", {}))
strip_datetime_pattern(base_config)

with Path(output_path).open("w", encoding="utf-8") as handle:
    yaml.safe_dump(base_config, handle, sort_keys=False)
PY
echo "snmp.yml written to /opt/monitoring-duo/snmp/ with lean ServerTech support."

# Additional instructions for prometheus.yml generation.
# Prompt user for path of prometheus.yml
SERVER_IP=$(hostname -I | awk '{print $1}')
while true; do
  echo ""
  echo "If you haven't generated the prometheus.yml file yet, follow these steps:"
  echo "  1. Ensure you have the repo hammerspace-grafana-dashboards by hammer-space cloned or on your CentOS system."
  echo "  2. Navigate to the installers folder"
  echo "      (cd /hammerspace-grafana-dashboards/installers/)"
  echo "  3. Run: ./config.py --sample_config"
  echo "      This generates the config_tooling.ini file needed for prometheus.yml"
  echo "  4. Enter default user/pass = admin/admin and set up a new password for Grafana"
  echo ""
  echo "      Access Grafana at: http://$SERVER_IP:3000"
  echo ""
  echo "  5. Navigate to the service accounts section and set up a new service account with the role of admin,"
  echo "      also generate a service token for your account."
  echo "      (Administration > Users and Access > Service Accounts)"
  echo "  6. Enter your grafana-service-account token and place the IP of the Hammerspace anvil where it says hammerspace1"
  echo "      in the config_tooling.ini file."
  echo "  7. Log into the anvil UI from browser (Google Chrome) with default credentials if you haven't done so already."
  echo "  8. Then run ./config.py --prometheus."
  echo ""
  echo "Example path: /root/hammerspace-grafana-dashboards/installers/prometheus.yml"
  echo ""
  echo "Please enter the full path to the generated prometheus.yml file."
  echo ""
  read -r PROM_YML_PATH
  if [[ -f "$PROM_YML_PATH" ]]; then
    cp "$PROM_YML_PATH" "$PROM_YML_TMP"
    if [[ -f /opt/monitoring-duo/config/prometheus.yml ]]; then
      backup_path="/opt/monitoring-duo/config/prometheus.yml.bak.$(date +%Y%m%d%H%M%S)"
      cp /opt/monitoring-duo/config/prometheus.yml "$backup_path"
      echo "Backed up existing prometheus.yml to $backup_path"
    fi
    python3 - "$PROM_YML_TMP" /opt/monitoring-duo/config/prometheus.yml <<'PY'
from pathlib import Path
import sys

import yaml


def normalize_snmp_job(job, snmp_endpoint):
    relabels = job.setdefault("relabel_configs", [])
    found = False
    for relabel in relabels:
        if relabel.get("target_label") == "__address__":
            relabel["replacement"] = snmp_endpoint
            found = True
    if not found:
        relabels.append({"target_label": "__address__", "replacement": snmp_endpoint})


source_path, output_path = sys.argv[1:3]
config = yaml.safe_load(Path(source_path).read_text()) or {}

for job in config.get("scrape_configs", []):
    job.pop("fallback_scrape_protocol", None)
    if job.get("metrics_path") == "/snmp":
        normalize_snmp_job(job, "localhost:9116")

Path(output_path).write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
PY
    echo "prometheus.yml normalized and copied to /opt/monitoring-duo/config/"
    break
  else
    echo ""
    echo "Error: prometheus.yml file not found at '$PROM_YML_PATH'. Please try again."
  fi
done

# Generate custom Dockerfile that builds a container that holds Prometheus and SNMP Exporter
# Update PROM_VERSION and SNMP_VERSION manually as newer versions are released
# *** NOTE: update LABEL maintainer ***
echo "Writing Dockerfile to /opt/monitoring-duo..."
cat <<'EOF' > /opt/monitoring-duo/Dockerfile
FROM debian:bullseye-slim

LABEL maintainer="Test Test user.name@email.com"

ENV PROM_VERSION=2.52.0
ENV SNMP_VERSION=0.26.0

RUN apt-get update && \
    apt-get install -y curl tar gzip && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/prometheus /snmp

RUN curl -sSL https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz \
    | tar -xz --strip-components=1 -C /usr/local/bin --wildcards '*/prometheus' '*/promtool'

RUN curl -sSL https://github.com/prometheus/snmp_exporter/releases/download/v${SNMP_VERSION}/snmp_exporter-${SNMP_VERSION}.linux-amd64.tar.gz \
    | tar -xz -C /usr/local/bin --strip-components=1 --wildcards '*/snmp_exporter'

COPY config/prometheus.yml /etc/prometheus/prometheus.yml
COPY snmp/snmp.yml /snmp/snmp.yml
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh
EXPOSE 9090 9116
ENTRYPOINT ["/entrypoint.sh"]
EOF
echo "Dockerfile created."
sleep 1

# Create entrypoint.sh script to launch both Prometheus + SNMP Exporter in the same container.
echo "Creating entrypoint.sh script..."
cat <<'EOF' > /opt/monitoring-duo/entrypoint.sh
#!/bin/bash
# entrypoint.sh
# launches both Prometheus + SNMP Exporter in the same container.

set -e

echo "Starting Prometheus..."
/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus &
PROM_PID=$!

# Handle graceful shutdown if container receives SIGINT/SIGTERM
trap "echo 'Stopping Prometheus...'; kill \$PROM_PID; exit" SIGINT SIGTERM

echo "Starting SNMP Exporter..."
/usr/local/bin/snmp_exporter \
  --config.file=/snmp/snmp.yml
wait "$PROM_PID"
EOF
chmod +x /opt/monitoring-duo/entrypoint.sh
echo "entrypoint.sh script created and made executable."

# Creation of docker-compose.yml
echo "Creating docker-compose.yml"
cat <<'EOF' > /opt/monitoring-duo/docker-compose.yml
services:
  prom-snmp:
    build: .
    container_name: prom-snmp-duo
    restart: unless-stopped
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./snmp/snmp.yml:/snmp/snmp.yml
    ports:
      - "9090:9090" # Prometheus
      - "9116:9116" # SNMP Exporter
EOF
echo "docker-compose.yml created at /opt/monitoring-duo/"

# Build the Docker image and start the container
echo "Building Docker image and starting the container..."
cd /opt/monitoring-duo
if docker compose up -d --build; then
  echo ""
  echo "Container launched successfully."
else
  echo ""
  echo "Docker build or launch failed. Check the logs above and fix any errors."
  exit 1
fi

# Brief pause before checking container status
sleep 2
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "================================================================="
echo "Access Prometheus at: http://$SERVER_IP:9090"
echo "Access SNMP Exporter at: http://$SERVER_IP:9116/metrics"
echo "Container name: prom-snmp-duo"
echo "Restart command: docker restart prom-snmp-duo"
echo ""
echo "Checking container status..."
docker ps --filter "name=prom-snmp-duo"
echo ""
echo "================================================================="
echo "Setup complete."
