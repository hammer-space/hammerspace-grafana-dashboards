#!/usr/bin/env python3
#
# Tooling for setting up prometheus and grafana when running on a local node
#

import os
import sys
import time
import argparse
import pathlib
import configparser
import glob
import json
import urllib
import getpass
import yaml
import urllib3
import requests as rq
import ipaddress

# Don't complain about self signed certs when connecting to the anvil
urllib3.disable_warnings()

#
# IPv6 address handling utilities
#

def format_ip_port(ip, port):
    """Format IP:port, wrapping IPv6 addresses in brackets"""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            return f'[{ip}]:{port}'
        else:
            return f'{ip}:{port}'
    except ValueError:
        # Not a valid IP, might be hostname
        return f'{ip}:{port}'

def format_url_host(host):
    """Format host for URL, wrapping IPv6 addresses in brackets"""
    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv6Address):
            return f'[{host}]'
        else:
            return host
    except ValueError:
        # Not a valid IP, might be hostname/FQDN
        return host

#
# Grafana dashboard setup and config
#

GRAFANA_SESSION = None
GRAFANA_URL = None
GRAFANA_PROMETHEUS_UID = None


def get_or_create_folder(folder_title):
    """
    Returns the folder ID for the given folder title.
    If folder does not exist, creates it.
    """
    # 1) Search for existing folder
    search_url = f"{GRAFANA_URL}/api/folders?limit=5000"
    resp = GRAFANA_SESSION.get(search_url)
    resp.raise_for_status()
    folders = resp.json()

    # Attempt to find the folder by matching the title
    for folder in folders:
        if folder.get("title") == folder_title:
            return folder["id"]

    # 2) Folder not found, create it
    create_url = f"{GRAFANA_URL}/api/folders"
    payload = {"title": folder_title}
    resp = GRAFANA_SESSION.post(create_url, data=json.dumps(payload))
    resp.raise_for_status()
    return resp.json()["id"]


def delete_dashboard(uid):
    """
    Deletes a dashboard by its UID.
    """
    delete_url = f"{GRAFANA_URL}/api/dashboards/uid/{uid}"
    resp = GRAFANA_SESSION.delete(delete_url)
    # 404 means it didn't exist, which is okay if we want to ensure it's gone
    if resp.status_code not in (200, 404):
        resp.raise_for_status()


def dashboard_exists(uid):
    """
    Check if a dashboard with the given UID exists.
    Returns True if it exists, False otherwise.
    """
    get_url = f"{GRAFANA_URL}/api/dashboards/uid/{uid}"
    resp = GRAFANA_SESSION.get(get_url)
    return (resp.status_code == 200)


def install_dashboards_from_path(args, folder_id, path_glob):
    """
    Install or update all dashboards found at path_glob (e.g. ../5.1/*.json)
    into the specified folder.
    """
    json_files = list(glob.glob(path_glob))
    if len(json_files) == 0:
        print(f'ERROR: No json dashboard files found at {path_glob}, exiting')
        sys.exit(1)

    for json_file in glob.glob(path_glob):
        with open(json_file, 'r', encoding='utf-8') as f:
            raw_dashboard = json.load(f)

        # Some dashboards come wrapped in { "dashboard": { ... }, "overwrite": true, ... }
        # Some have them directly as a top-level dict. Let's unify it:
        if 'dashboard' in raw_dashboard:
            dashboard_json = raw_dashboard['dashboard']
        else:
            dashboard_json = raw_dashboard

        # Replace ${DS_PROMETHEUS} variables with the actual datasource UID
        # This is necessary when using /api/dashboards/db instead of /api/dashboards/import
        dashboard_str = json.dumps(dashboard_json)
        dashboard_str = dashboard_str.replace('${DS_PROMETHEUS}', GRAFANA_PROMETHEUS_UID)
        dashboard_json = json.loads(dashboard_str)

        # Remove __inputs section if present (not needed with /api/dashboards/db)
        if '__inputs' in dashboard_json:
            del dashboard_json['__inputs']

        # Update templating variable if it exists
        if 'templating' in dashboard_json and 'list' in dashboard_json['templating']:
            for var in dashboard_json['templating']['list']:
                if var.get('name') == 'DS_PROMETHEUS':
                    # Convert the template variable to use the specific datasource
                    var['current'] = {
                        'selected': True,
                        'text': args.datasource_name,
                        'value': GRAFANA_PROMETHEUS_UID
                    }
                    var['hide'] = 2  # Hide variable from UI
                    var['query'] = GRAFANA_PROMETHEUS_UID
                    var['type'] = 'datasource'

        # Make sure there's a UID
        uid = dashboard_json.get('uid')
        print(f"Setting up dashboard: {dashboard_json.get('title')}")
        if not uid:
            print(f"Warning: Dashboard {json_file} has no UID. Grafana will generate one if missing.")
            print('Aborting')
            sys.exit(1)

        # Check if the dashboard already exists
        if uid and dashboard_exists(uid):
            choice = 'n'
            if not args.force:
                print(f"\nDashboard '{dashboard_json.get('title')}' with UID '{uid}' already exists.")
                choice = input("Do you want to overwrite? [y/N]: ").strip().lower()

            if (not args.force) and (not choice.startswith('y')):
                print("Skipping reinstall")
                continue

        # Now upload (create or update) the dashboard
        post_url = f"{GRAFANA_URL}/api/dashboards/db"
        payload = {
            "dashboard": dashboard_json,
            "folderId": folder_id,
            "overwrite": True
        }
        resp = GRAFANA_SESSION.post(post_url, data=json.dumps(payload))
        if resp.status_code not in (200, 202):  # Typically 200 OK or 202 Accepted
            print(f"Error installing dashboard from {json_file}: {resp.text}")
        else:
            print(f"Installed dashboard from {json_file} in folder ID {folder_id}")


def setup_grafana_session(args):
    global GRAFANA_URL
    global GRAFANA_SESSION

    default_token = 'REPLACE_ME_WITH_ADMIN_SERVICE_ACCONT_TOKEN'
    instructions_url = "https://grafana.com/docs/grafana/latest/administration/service-accounts/#to-create-a-service-account"

    token = args.config['token']
    if token == default_token:
        print(f'ERR: No grafana service account token found in {CONFIG_FILE}\n')
        print("Please follow the instructions at the below URL to:")
        print("  1) in grafana, generate an admin capable service account")
        print("  2) in grafana, generate an admin capable token in that service account")
        print(f"  3) add the token to the config file {CONFIG_FILE}")
        print("  4) re-run this script with --grafana")
        print()
        print(f"  {instructions_url}")
        sys.exit(1)

    GRAFANA_URL = args.config['grafana_url'].rstrip('/')

    # Set up HTTP GRAFANA_SESSION with auth header
    GRAFANA_SESSION = rq.Session()
    GRAFANA_SESSION.headers.update({
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    })

    # Test the connection to detect SSL/protocol mismatches
    test_url = f"{GRAFANA_URL}/api/health"
    try:
        resp = GRAFANA_SESSION.get(test_url)
        # Even if we get a 401 (auth issue), the connection itself worked
        if resp.status_code not in (200, 401):
            print(f"Warning: Grafana health check returned status {resp.status_code}")
    except rq.exceptions.SSLError as e:
        print(f"\nERROR: SSL/Protocol mismatch connecting to Grafana at {GRAFANA_URL}")
        print(f"\nThis usually happens when the URL protocol doesn't match Grafana's configuration:")
        print(f"  - If you specified https:// but Grafana uses HTTP, change to http://")
        print(f"  - If you specified http:// but Grafana uses HTTPS, change to https://")
        print(f"\nPlease update the grafana_url in {CONFIG_FILE}")
        print(f"Current URL: {GRAFANA_URL}")
        sys.exit(1)
    except rq.exceptions.ConnectionError as e:
        print(f"\nERROR: Cannot connect to Grafana at {GRAFANA_URL}")
        print(f"\nPlease verify:")
        print(f"  1. Grafana is running")
        print(f"  2. The URL and port are correct in {CONFIG_FILE}")
        print(f"  3. No firewall is blocking the connection")
        sys.exit(1)

    # Verify the token has admin permissions
    auth_url = f"{GRAFANA_URL}/api/org/users"
    try:
        resp = GRAFANA_SESSION.get(auth_url)
        if resp.status_code == 401:
            print(f"\nERROR: Authentication failed - invalid token")
            print(f"Please verify the service account token in {CONFIG_FILE}")
            sys.exit(1)
        elif resp.status_code == 403:
            print(f"\nERROR: Token does not valid or does not have admin permissions")
            print(f"Please verify and/or regenerate the service account token in {CONFIG_FILE}")
            sys.exit(1)
        elif resp.status_code != 200:
            print(f"Warning: Could not verify admin permissions (status {resp.status_code})")
    except Exception as e:
        print(f"Warning: Could not verify permissions: {e}")


def install_grafana_dashboards(args):
    """
    Installs Grafana dashboards from 5.1/*.json and 5.0/*.json into:
      - Hammerspace 5.1 and later
      - Hammerspace 5.0
    respectively. If a dashboard already exists, prompts to delete before reinstalling.
    Ensures each dashboard uses the 'Prometheus' data source.
    """

    # Retrieve or create the two folders
    folder_51_id = get_or_create_folder("Hammerspace 5.1 and later")
    folder_50_id = get_or_create_folder("Hammerspace 5.0")

    script_path = str(pathlib.Path(__file__).absolute().parent.parent)
    # 1) Install dashboards in Hammerspace 5.1 and later
    install_dashboards_from_path(args, folder_51_id, os.path.join(script_path, "5.1", "*.json"))

    # 2) Install dashboards in Hammerspace 5.0
    install_dashboards_from_path(args, folder_50_id, os.path.join(script_path, "5.0", "*.json"))

    print("All dashboards have been processed.")


def setup_prometheus_datasource_in_grafana(args):
    """
    Sets up (or updates) a Prometheus datasource named 'Prometheus'
    pointing to http://localhost:9090 in Grafana.
    """
    global GRAFANA_PROMETHEUS_UID

    # Check if datasource "Prometheus" already exists
    get_url = f"{args.config['grafana_url']}/api/datasources/name/{args.datasource_name}"
    resp = GRAFANA_SESSION.get(get_url)

    # Define the datasource settings you want
    datasource_payload = {
        "name": args.datasource_name,
        "type": "prometheus",
        "url": "http://localhost:9090",
        "access": "proxy",        # or "server" depending on your need
        "basicAuth": False,       # or True if you need basic auth
        "editable": True,         # let it be editable in the UI
        # Additional Prometheus options, if you wish:
        # "jsonData": {
        #     "timeInterval": "5s"
        # }
    }

    if resp.status_code == 200:
        # The datasource already exists, do nothing
        print(f"Grafana datasource '{args.datasource_name}' already exists, not modifying")
    elif resp.status_code == 404:
        # The datasource does not exist; create it
        create_url = f"{args.config['grafana_url']}/api/datasources"
        create_resp = GRAFANA_SESSION.post(create_url, data=json.dumps(datasource_payload))
        if create_resp.status_code not in (200, 201):
            print(f"Failed to create datasource 'Prometheus': {create_resp.text}")
        else:
            print("Datasource 'Prometheus' created successfully.")
    else:
        # Some other unexpected error
        print(f"Error checking existing datasource: {resp.status_code} - {resp.text}")

    resp = GRAFANA_SESSION.get(get_url)
    if resp.status_code == 200:
        GRAFANA_PROMETHEUS_UID = resp.json()['uid']
    else:
        print(f"ERROR: Could not retrieve datasource UID. Status: {resp.status_code}")
        sys.exit(1)

    # Test that the Prometheus datasource is actually working
    print("Testing Prometheus datasource connectivity...")
    query_url = f"{GRAFANA_URL}/api/datasources/proxy/uid/{GRAFANA_PROMETHEUS_UID}/api/v1/query"
    test_query = {"query": "up"}  # Simple query to check if Prometheus has any metrics

    try:
        resp = GRAFANA_SESSION.get(query_url, params=test_query)
        if resp.status_code == 200:
            result = resp.json()
            if result.get('status') == 'success':
                metric_count = len(result.get('data', {}).get('result', []))
                if metric_count > 0:
                    print(f"✓ Prometheus datasource is working ({metric_count} targets found)")
                else:
                    print("WARNING: Prometheus datasource is reachable but has no 'up' metrics")
                    print("This might indicate Prometheus is not scraping any targets yet")
                    choice = input("Continue anyway? [y/N]: ").strip().lower()
                    if not choice.startswith('y'):
                        print("Aborting dashboard installation")
                        sys.exit(1)
            else:
                print(f"ERROR: Prometheus query failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
        elif resp.status_code == 502 or resp.status_code == 503:
            print(f"ERROR: Cannot reach Prometheus at http://localhost:9090")
            print("Please verify:")
            print("  1. Prometheus is running on localhost:9090")
            print("  2. Prometheus is accessible from the Grafana server")
            sys.exit(1)
        else:
            print(f"ERROR: Failed to test Prometheus datasource. Status: {resp.status_code}")
            print(f"Response: {resp.text}")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to test Prometheus datasource: {e}")
        sys.exit(1)

#
# Prometheus Config Generation
#


class AnvilSM(object):
    """This class is for common/simple interactions with datasphere's REST api,
       please don't do anything complicated with it"""
    def __init__(self, ssl_verify=False):
        self.baseurl = ""
        self.apiurl = ""
        self.cliurl = ""
        self.session = None
        self.ssl_verify = ssl_verify

    def set_base_url(self, url):
        self.baseurl = url
        self.apiurl = url + '/mgmt/v1.2/rest'
        self.cliurl = url + '/cli/v1.2/rest/cli'

    def auth_local(self):
        """Used for authenticating without passwords when running directly on the primary datasphere"""
        self.set_base_url('http://127.0.0.1:8080')
        self.session = rq.Session()
        self.session.verify = self.ssl_verify
        self.session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json', 'X-Admin': 'admin'})

    def get_creds(self, user=None, passwd=None):
        if user is None and 'ANVIL_USER' in os.environ:
            user = os.environ['ANVIL_USER']
        if passwd is None and 'ANVIL_PASSWORD' in os.environ:
            passwd = os.environ['ANVIL_PASSWORD']
        if user is None or passwd is None:
            print(f'\nConnecting to anvil {self.baseurl}, please provide credentials you use to login to the GUI')
            user = input('anvil username: ')
            passwd = getpass.getpass('anvil password: ')
        return user, passwd

    def auth_creds(self, url, user=None, passwd=None):
        if not url.startswith('http'):
            url = 'https://' + format_url_host(url)
        self.set_base_url(url)
        self.session = rq.Session()
        self.session.verify = self.ssl_verify

        user, passwd = self.get_creds(user, passwd)

        # Login to REST api
        try:
            r = self.session.post(self.apiurl + "/login", data={"username": user, "password": passwd})
        except rq.exceptions.ConnectionError as e:
            errstr = str(e)
            if "Connection refused" in errstr:
                print(f'Hammerspace not reachable due to "Connection refused" at {self.baseurl}')
                print('    check hostname/ip and routing')
                sys.exit(1)
            elif "No route to host" in errstr:
                print(f'Hammerspace not reachable due to "No route to host" at {self.baseurl}')
                print('    check hostname/ip and routing')
                print('    check that you are accessing a management interface and that port 443 is open')
                sys.exit(1)
            else:
                print(f'Hammerspace not reachable due at {self.baseurl}')
                print(f'    {errstr}')
                sys.exit(1)
        if r.status_code != 200:
            print("Failed to login, check username/password and datasphere hostname or ip")
            print(f'HTTP status code: {r.status_code}')
            print(f'HTTP reason: {r.reason}')
            sys.exit(1)

    def get_storage_volumes(self):
        r = self.session.get(self.apiurl + "/storage-volumes")
        volumes_json = r.json()
        # with open("volumes.json", "w") as f:
        #     json.dump(volumes_json, f, indent=4, sort_keys=True)
        volumes_detail = []
        for volume in volumes_json:
            if volume.get('_type') == "STORAGE_VOLUME":
                res = {}
                res['node_name'] = volume['node']['name']
                res['name'] = volume['name']
                res['path'] = volume['logicalVolume']['exportPath']
                res['ip'] = volume['logicalVolume']['ipAddresses'][0]['address']
                res['id'] = int(volume['internalId'])
                res['full_json'] = volume
            volumes_detail.append(res)
        return volumes_detail

    def get_object_volumes(self):
        r = self.session.get(self.apiurl + "/object-storage-volumes")
        ov_json = r.json()
        # with open("volumes.json", "w") as f:
        #     json.dump(volumes_json, f, indent=4, sort_keys=True)
        ov_detail = []
        for volume in ov_json:
            if volume.get('_type') == "OBJECT_STORAGE_VOLUME":
                res = {}
                res['node_name'] = volume['node']['name']
                res['name'] = volume['name']
                res['id'] = int(volume['internalId'])
                res['full_json'] = volume
            ov_detail.append(res)
        return ov_detail

    def get_shares(self):
        r = self.session.get(self.apiurl + "/shares")
        shares_json = r.json()
        # with open("shares.json", "w") as f:
        #     json.dump(shares_json, f, indent=4, sort_keys=True)
        shares_detail = []
        for share in shares_json:
            res = {}
            res['path'] = share['path']
            res['id'] = int(share['internalId'])
            res['name'] = share['name']
            res['num_files'] = int(share['totalNumberOfFiles'])
            res['full_json'] = share
            shares_detail.append(res)
        return shares_detail

    def get_nodes(self):
        r = self.session.get(self.apiurl + "/nodes")
        nodes_json = r.json()
        # with open("nodes.json", "w") as f:
        #     json.dump(nodes_json, f, indent=4, sort_keys=True)
        nodes_detail = []
        for node in nodes_json:
            if node.get('_type') == "NODE":
                res = {}
                res['name'] = node['name']
                res['id'] = int(node['internalId'])
                res['ip_mgmt'] = []
                res['ip_portal'] = []
                res['ip_ha'] = []
                res['ip_data'] = []
                for svc in node['platformServices']:
                    if svc['_type'] == "NETWORK_IF":
                        for role in svc['roles']:
                            if role == "DATA":
                                for addr in svc['ipAddresses']:
                                    res['ip_data'].append(addr['address'])
                            elif role == "MGMT":
                                for addr in svc['ipAddresses']:
                                    res['ip_mgmt'].append(addr['address'])
                            elif role == "PORTAL":
                                for addr in svc['ipAddresses']:
                                    res['ip_portal'].append(addr['address'])
                            elif role == "HA":
                                for addr in svc['ipAddresses']:
                                    res['ip_ha'].append(addr['address'])
                            else:
                                print(f'WARNING: get_nodes(): Unhandled network role named {role}, please report a bug')
                res['services'] = set()
                for svc in node['systemServices']:
                    if svc['_type'] == "DATA_SPHERE" and svc['dataDirectorRole'] == "PRIMARY":
                        res['services'].add("DATA_SPHERE_PRIMARY")
                    elif svc['_type'] == "DATA_SPHERE":
                        res['services'].add("DATA_SPHERE_SECONDARY")
                    elif svc['_type'] == "DATA_MOVER" and svc['operState'] == "UP":
                        res['services'].add("DATA_MOVER")
                    elif svc['_type'] == "CLOUD_MOVER" and svc['operState'] == "UP":
                        res['services'].add("CLOUD_MOVER")
                    elif svc['_type'] == "CTDB" and svc['operState'] == "UP":
                        res['services'].add("CTDB")
                    elif svc['_type'] == "DATA_PORTAL" and svc['operState'] == "UP" and svc['dataPortalType'] == "SMB":
                        res['services'].add("DATA_PORTAL_SMB")
                    elif svc['_type'] == "DATA_PORTAL" and svc['operState'] == "UP" and svc['dataPortalType'] == "NFS_V3":
                        res['services'].add("DATA_PORTAL_NFS3")
                res['full_json'] = node
                nodes_detail.append(res)
        return nodes_detail

    def get_cluster(self):
        r = self.session.get(self.apiurl + "/cntl")
        cntl_json = r.json()
        return cntl_json

    def get_file_info(self, fn):
        # DataSphere requires the <space> character to be replaced with %20
        # DataSphere ALSO requires the '/' in the path to be replaced by %2F
        # I cannot find (more study needed) an elegant way to do both at the same time
        enfn = urllib.quote_plus(fn)
        enfn = enfn.replace('+', '%20')
        r = self.session.get(self.apiurl + "/files/" + enfn)
        file_json = r.json()
        return file_json

    def get_objectives(self):
        r = self.session.get(self.apiurl + "/objectives/")
        obj_json = r.json()
        return obj_json

    def get_elemental_objectives(self):
        r = self.session.get(self.apiurl + "/elemental-objectives/")
        obj_json = r.json()
        return obj_json

    def get_report(self, thetype):
        r = self.session.get(self.apiurl + '/reports/' + thetype)
        obj_json = r.json()
        return obj_json


class ClusterInfo(object):
    def __init__(self):
        self.anvil_floating_ip = None
        self.dsx_physical_ips = []
        self.anvil_physical_ips = []
        self.ip_to_hostname = {}
        self.cluster_name = None


def build_prometheus_config(args):
    clusters = []
    for cluster_config in args.config['clusters']:
        # Handle both old format (string) and new format (dict with name/address)
        if isinstance(cluster_config, dict):
            anvil_ip = cluster_config['address']
            config_cluster_name = cluster_config['name']
        else:
            # Fallback for old format
            anvil_ip = cluster_config
            config_cluster_name = None

        asm = AnvilSM()
        asm.auth_creds(anvil_ip)
        nodes = asm.get_nodes()
        cluster = asm.get_cluster()
        clusters.append((cluster, nodes, config_cluster_name))

    cinfos = []
    for clust, nodes, config_cluster_name in clusters:
        ci = ClusterInfo()
        cinfos.append(ci)
        ci.anvil_floating_ip = clust[0]['mgmtIps'][0]['address']
        # Use config name if provided, otherwise fallback to cluster's own name
        ci.cluster_name = config_cluster_name if config_cluster_name else clust[0]['name']
        for node in nodes:
            if ('DATA_SPHERE_PRIMARY' in node['services']
                    or 'DATA_SPHERE_SECONDARY' in node['services']):
                ip = node['ip_mgmt'][0]
                ci.anvil_physical_ips.append(ip)
                ci.ip_to_hostname[ip] = node['name']
            elif 'DATA_MOVER' in node['services']:
                ip = node['ip_mgmt'][0]
                ci.dsx_physical_ips.append(ip)
                ci.ip_to_hostname[ip] = node['name']

    prom_config = {}
    prom_config['alerting'] = {
        'alertmanagers': [{'static_configs': [{'targets': ['localhost:9093']}]}]}
    prom_config['global'] = {
        'evaluation_interval': '15s',
        'external_labels': {'monitor': 'example'},
        'scrape_interval': '15s',
    }
    prom_config['rule_files'] = ['/etc/prometheus/rules.d/default.rules.yml']

    scr_conf = []
    prom_config['scrape_configs'] = scr_conf
    scr_conf.append(
        {
            'job_name': 'prometheus',
            'fallback_scrape_protocol':'PrometheusText0.0.4',
            'static_configs': [
                {'labels': {'node_type': 'prometheus'}},
                {'targets': ['localhost:9090']}
            ],
        },
    )

    # Active anvil exporters
    static_configs = []
    for i in range(len(cinfos)):
        ci = cinfos[i]
        cluster_targets = []
        for exporter, port in [
                ('dme_exporter', '9101'),
                ('protod_exporter', '9102'),
                ('filesystem_exporter', '9103'),
                ]:
            cluster_targets.append(format_ip_port(ci.anvil_floating_ip, port))

        static_configs.append({
                'labels': {
                    'node_type': 'clusterip',
                    'instance': ci.cluster_name,
                    'cluster': ci.cluster_name,
                    },
                'targets': cluster_targets, })
    job = {
        'job_name': 'cluster',
        'fallback_scrape_protocol': 'PrometheusText0.0.4',
        'static_configs': static_configs,
        }
    scr_conf.append(job)

    # Anvil nodes
    static_configs = []
    for i in range(len(cinfos)):
        ci = cinfos[i]
        for anvilip in ci.anvil_physical_ips:
            node_name = ci.ip_to_hostname[anvilip]
            anvil_targets = []
            for exporter, port in [
                    ('prometheus_exporter', '9100'),
                    ]:
                anvil_targets.append(format_ip_port(anvilip, port))

            static_config = {
                'labels': {
                    'node_type': 'anvil',
                    'instance': node_name,
                    'cluster': ci.cluster_name,
                    },
                'targets': anvil_targets,
                }
            static_configs.append(static_config)

    job = {
        'job_name': 'anvil_nodes',
        'fallback_scrape_protocol': 'PrometheusText0.0.4',
        'static_configs': static_configs,
        }
    scr_conf.append(job)

    # DSX nodes
    static_configs = []
    for i in range(len(cinfos)):
        ci = cinfos[i]
        for dsxip in ci.dsx_physical_ips:
            node_name = ci.ip_to_hostname[dsxip]
            dsx_targets = []
            for exporter, port in [
                    ('prometheus_exporter', '9100'),
                    ('cloud_mover_exporter', '9105'),
                    ]:
                dsx_targets.append(format_ip_port(dsxip, port))

            static_config = {
                'labels': {
                    'node_type': 'dsx',
                    'instance': node_name,
                    'cluster': ci.cluster_name,
                    },
                'targets': dsx_targets,
                }
            static_configs.append(static_config)

    job = {
        'job_name': 'dsx_nodes',
        'fallback_scrape_protocol': 'PrometheusText0.0.4',
        'static_configs': static_configs,
        }
    scr_conf.append(job)

    print(f'Dumping promethus yaml config to {args.prometheus_output}')
    with open(args.prometheus_output, 'w') as fd:
        yaml.dump(prom_config, stream=fd, sort_keys=False)

#
# Config file
#


SCRIPT_DIR = pathlib.Path(__file__).absolute().parent
CONFIG_FILE = SCRIPT_DIR / 'config_tooling.ini'


def get_config():
    default_token = 'REPLACE_ME_WITH_ADMIN_SERVICE_ACCONT_TOKEN'
    instructions_url = "https://grafana.com/docs/grafana/latest/administration/service-accounts/#to-create-a-service-account"

    config = configparser.ConfigParser()
    config['hosts'] = {
        'grafana_url': 'http://localhost:3000',
        'prometheus_url': 'http://localhost:9090',
    }
    config['clusters'] = {
        '; hammerspace1_name': 'Cluster1',
        '; hammerspace1_address': '1.1.1.1',
        '; ': "To configure more than one hammerspace cluster, add multiple hammerspace* entries to this section",
        '; ': "Each cluster needs a _name and _address entry. If only one cluster is needed remove the excess example lines",
        '; ': "Name will be used as the 'cluster' label on every metric in Prometheus and Grafana so make it succinct and meaningful"
    }
    config['grafana_service_account'] = {
        'token': default_token
    }

    if not CONFIG_FILE.is_file():
        print(f'{CONFIG_FILE} not found, generating')
        with CONFIG_FILE.open('w') as fd:
            config.write(fd)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Token validation moved to setup_grafana_session() where it's actually needed

    clusters = []
    # Parse new format: hammerspace1_name, hammerspace1_address, etc.
    cluster_prefixes = set()
    for k in config['clusters'].keys():
        if k.lower().startswith('hammerspace') and '_' in k:
            prefix = k.rsplit('_', 1)[0]
            cluster_prefixes.add(prefix)

    for prefix in sorted(cluster_prefixes):
        name_key = f"{prefix}_name"
        address_key = f"{prefix}_address"
        if name_key in config['clusters'] and address_key in config['clusters']:
            cluster_info = {
                'name': config['clusters'][name_key],
                'address': config['clusters'][address_key]
            }
            clusters.append(cluster_info)

    ret_config = {
        'token': config['grafana_service_account']['token'],
        'grafana_url': config['hosts']['grafana_url'],
        'prom_url': config['hosts']['prometheus_url'],
        'clusters': clusters,
    }
    return ret_config


def add_cluster(cluster_address, name=None, username=None, password=None):
    """Add a new cluster to the config file"""
    if not CONFIG_FILE.is_file():
        print(f'Config file not found, creating {CONFIG_FILE}...')
        # Create the config file by calling get_config which handles creation
        get_config()

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Check if this address already exists
    for key in config['clusters'].keys():
        if key.lower().endswith('_address') and config['clusters'][key] == cluster_address:
            prefix = key.rsplit('_', 1)[0]
            name_key = f"{prefix}_name"
            existing_name = config['clusters'].get(name_key, 'Unknown')
            print(f'ERROR: Cluster at {cluster_address} already exists as "{existing_name}"')
            print(f'To update, first remove it with: --remove-cluster {cluster_address}')
            sys.exit(1)

    # Connect to the cluster to get its name (if not provided)
    if name:
        cluster_name = name
        print(f'Using provided cluster name: "{cluster_name}"')
        print(f'Connecting to Hammerspace cluster at {cluster_address} to verify...')
        asm = AnvilSM()
        asm.auth_creds(cluster_address, user=username, passwd=password)
        print(f'Successfully connected to cluster at {cluster_address}')
    else:
        print(f'Connecting to Hammerspace cluster at {cluster_address}...')
        asm = AnvilSM()
        asm.auth_creds(cluster_address, user=username, passwd=password)
        cluster_info = asm.get_cluster()
        cluster_name = cluster_info[0]['name']
        print(f'Successfully connected to cluster "{cluster_name}"')

    # Find the next available hammerspace number
    cluster_nums = []
    for key in config['clusters'].keys():
        if key.lower().startswith('hammerspace') and '_' in key:
            try:
                num = int(key.split('hammerspace')[1].split('_')[0])
                cluster_nums.append(num)
            except (ValueError, IndexError):
                pass

    next_num = max(cluster_nums) + 1 if cluster_nums else 1

    # Add the cluster
    name_key = f'hammerspace{next_num}_name'
    address_key = f'hammerspace{next_num}_address'

    config['clusters'][name_key] = cluster_name
    config['clusters'][address_key] = cluster_address

    with CONFIG_FILE.open('w') as fd:
        config.write(fd)

    print(f'Successfully added cluster "{cluster_name}" at {cluster_address}')


def remove_cluster(cluster_address):
    """Remove a cluster from the config file by its address"""
    if not CONFIG_FILE.is_file():
        print(f'ERROR: Config file {CONFIG_FILE} not found.')
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Find the cluster with matching address
    found = False
    prefix_to_remove = None
    cluster_name = None

    for key in config['clusters'].keys():
        if key.lower().endswith('_address') and config['clusters'][key] == cluster_address:
            prefix_to_remove = key.rsplit('_', 1)[0]
            name_key = f"{prefix_to_remove}_name"
            if name_key in config['clusters']:
                cluster_name = config['clusters'][name_key]
            found = True
            break

    if not found:
        print(f'ERROR: No cluster found with address {cluster_address}')
        sys.exit(1)

    # Remove both name and address keys
    name_key = f"{prefix_to_remove}_name"
    address_key = f"{prefix_to_remove}_address"

    if name_key in config['clusters']:
        del config['clusters'][name_key]
    if address_key in config['clusters']:
        del config['clusters'][address_key]

    with CONFIG_FILE.open('w') as fd:
        config.write(fd)

    cluster_desc = f'"{cluster_name}" at {cluster_address}' if cluster_name else cluster_address
    print(f'Successfully removed cluster {cluster_desc}')


def add_token(token):
    """Add Grafana service account token to the config file"""
    if not CONFIG_FILE.is_file():
        print(f'Config file not found, creating {CONFIG_FILE}...')
        get_config()

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Update the token
    config['grafana_service_account']['token'] = token

    with CONFIG_FILE.open('w') as fd:
        config.write(fd)

    print(f'Successfully added Grafana service account token to {CONFIG_FILE}')


def set_grafana_url(url):
    """Set Grafana URL in the config file"""
    if not CONFIG_FILE.is_file():
        print(f'Config file not found, creating {CONFIG_FILE}...')
        get_config()

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Update the Grafana URL
    config['hosts']['grafana_url'] = url

    with CONFIG_FILE.open('w') as fd:
        config.write(fd)

    print(f'Successfully set Grafana URL to {url} in {CONFIG_FILE}')


def set_prometheus_url(url):
    """Set Prometheus URL in the config file"""
    if not CONFIG_FILE.is_file():
        print(f'Config file not found, creating {CONFIG_FILE}...')
        get_config()

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    # Update the Prometheus URL
    config['hosts']['prometheus_url'] = url

    with CONFIG_FILE.open('w') as fd:
        config.write(fd)

    print(f'Successfully set Prometheus URL to {url} in {CONFIG_FILE}')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--create-config-ini', action='store_true', help=f'Step 1: Generate a config file at {CONFIG_FILE}')
    p.add_argument('--add-cluster', metavar='<cluster-ip-or-hostname>', help=f'Add a cluster to {CONFIG_FILE}')
    p.add_argument('--name', metavar='<short-nice-name>', help='Optional cluster name to use instead of fetching from cluster')
    p.add_argument('--username', metavar='<admin-username>', help='Admin username for cluster authentication (optional, will prompt if not provided)')
    p.add_argument('--password', metavar='<admin-password>', help='Admin password for cluster authentication (optional, will prompt if not provided)')
    p.add_argument('--remove-cluster', metavar='<cluster-ip-or-hostname>', help=f'Remove a cluster from {CONFIG_FILE}')
    p.add_argument('--add-token', metavar='<grafana-service-account-token>', help=f'Add Grafana service account token to {CONFIG_FILE}')
    p.add_argument('--grafana-url', metavar='<url>', help=f'Set Grafana URL in {CONFIG_FILE}')
    p.add_argument('--prometheus-url', metavar='<url>', help=f'Set Prometheus URL in {CONFIG_FILE}')
    p.add_argument('--prometheus', action='store_true', help=f'Step 2: Generate prometheus.yml from cluster(s) in {CONFIG_FILE}')
    p.add_argument('--grafana', action='store_true', help='Step 3: Setup Grafana datasource and install dashboards')
    p.add_argument('-f', '--force', action='store_true', help="Don't prompt about overwriting existing grafana dashboards")

    args = p.parse_args()
    args.datasource_name = "Prometheus"
    args.prometheus_output = 'prometheus.yml'

    # Track if any configuration commands are run
    config_command_run = False

    if args.create_config_ini:
        if CONFIG_FILE.is_file():
            p.exit(f'ERROR: Not overwriting existing config file {CONFIG_FILE}')
        args.config = get_config()
        config_command_run = True

    if args.add_cluster:
        add_cluster(args.add_cluster, name=args.name, username=args.username, password=args.password)
        config_command_run = True

    if args.remove_cluster:
        remove_cluster(args.remove_cluster)
        config_command_run = True

    if args.add_token:
        add_token(args.add_token)
        config_command_run = True

    if args.grafana_url:
        set_grafana_url(args.grafana_url)
        config_command_run = True

    if args.prometheus_url:
        set_prometheus_url(args.prometheus_url)
        config_command_run = True

    # If any config commands were run, exit now
    if config_command_run:
        p.exit()

    # Otherwise, proceed with prometheus/grafana operations
    args.config = get_config()

    if args.prometheus:
        build_prometheus_config(args)

    if args.grafana:
        setup_grafana_session(args)
        setup_prometheus_datasource_in_grafana(args)
        install_grafana_dashboards(args)


if __name__ == '__main__':
    main()
