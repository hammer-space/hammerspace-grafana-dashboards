#!/bin/bash

# Intro and User confirmation
echo ""
echo "================================================================="
echo "Grafana + Prometheus Setup for CentOS 8.5+ Systems"
echo "================================================================="
echo ""
echo "This script will:"
echo " - Install needed modules and packages."
echo " - Install Docker and Docker compose v2 if needed."
echo " - Install Grafana natively (unless already running)."
echo " - Prompt user for full file path to prometheus.yml after generation with instructions."
echo " - Build a Docker container with Prometheus."
echo ""
echo "IMPORTANT:"
echo " - Ensure you also have the repository hammerspace-grafana-dashboards from hammer-space cloned or on your CentOS environment."
echo "   (Needed for generation of prometheus.yml)"
echo " - You may run this script first to install Grafana and needed packages, it will stop and prompt for the prometheus.yml file path after."
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

# centos_prom_grafa.sh
# Automates Docker-based installation of Prometheus and Grafana on CentOS 8.5+
set -euo pipefail
echo "Starting Prometheus + Grafana setup on CentOS..."
# Check for root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Exiting."
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

# Check for docker
if ! command -v docker &> /dev/null; then
  echo "Docker not found. Installing..."
  dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
  dnf install -y docker-ce docker-ce-cli containerd.io
  systemctl enable docker
  systemctl start docker
  echo "Docker  installed and started."
else
  echo "Docker is already installed."
fi

# Check for Docker Compose v2
if ! docker compose version &> /dev/null; then
  echo "Docker Compose v2 is not found. Installing..."
  mkdir -p ~/.docker/cli-plugins
  curl -SL https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-linux-x86_64 \
    -o ~/.docker/cli-plugins/docker-compose
  chmod +x ~/.docker/cli-plugins/docker-compose
  echo "Docker Compose v2 installed."
else
  echo "Docker Compose v2 is already installed."
fi

# Set up project structure and base config
echo "Creating directory structure under /opt/monitoring..."
mkdir -p /opt/monitoring/config
cat <<EOF > /opt/monitoring/docker-compose.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
EOF

cat <<EOF > /etc/yum.repos.d/grafana.repo
[grafana]
name=Grafana OSS
baseurl=https://packages.grafana.com/oss/rpm
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://packages.grafana.com/gpg.key
EOF

# Installing Grafana natively from official repo
echo "Installing Grafana via dnf..."
dnf install -y grafana
systemctl daemon-reexec
systemctl enable --now grafana-server
echo "Grafana installed and running. you can access it on port 3000 (default user/pass: admin/admin)"

# Prompt user to open required ports.
echo ""
while true; do
  read -p "Would you like to open firewall ports for Grafana (3000) and Prometheus (9090)? (y/n): " confirm
  if [[ $confirm =~ ^[Yy]$ || $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
    firewall-cmd --add-port=3000/tcp --permanent
    firewall-cmd --add-port=9090/tcp --permanent
    firewall-cmd --reload
    echo "Ports 3000 and 9090 are now open."
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
    cp "$PROM_YML_PATH" /opt/monitoring/config/prometheus.yml
    if [[ -f /opt/monitoring/config/prometheus.yml ]]; then
      echo "prometheus.yml copied to /opt/monitoring/config/"
      break
    else
      echo "Warning: prometheus.yml copy may have failed. Please verify manually."
    fi
  else
    echo ""
    echo "Error: prometheus.yml file not found at '$PROM_YML_PATH'. Please try again."
  fi
done

# Starting Docker containers
echo "Starting Prometheus container..."
cd /opt/monitoring
docker compose up -d

echo "Containers started. Checking status..."
# Brief pause before checking container status
sleep 2
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "================================================================="
echo "Access Prometheus at: http://$SERVER_IP:9090"
echo "Access Grafana at: http://$SERVER_IP:3000"
echo ""
echo "Checking container status..."
docker ps --filter "name=prometheus"
echo ""
echo "================================================================="
echo "Setup complete."