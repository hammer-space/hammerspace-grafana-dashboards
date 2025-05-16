#!/usr/bin/env python3
#
# Tooling for setting up prometheus and grafana when running on a local node
#

import os
import sys
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

# Don't complain about self signed certs when connecting to the anvil
urllib3.disable_warnings()

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

        # Make sure there's a UID
        uid = dashboard_json.get('uid')
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
            "overwrite": True,
            # Use inputs to specify the value of, this doesn't seem to work :(
            # See the forcing function above for the variables in the templating section
            "inputs": [
                {
                    "name": "DS_PROMETHEUS",
                    "type": "datasource",
                    "pluginId": "prometheus",
                    "value": GRAFANA_PROMETHEUS_UID,
                }]
        }
        resp = GRAFANA_SESSION.post(post_url, data=json.dumps(payload))
        if resp.status_code not in (200, 202):  # Typically 200 OK or 202 Accepted
            print(f"Error installing dashboard from {json_file}: {resp.text}")
        else:
            print(f"Installed dashboard from {json_file} in folder ID {folder_id}")


def setup_grafna_session(args):
    global GRAFANA_URL
    global GRAFANA_SESSION
    GRAFANA_URL = args.config['grafana_url'].rstrip('/')
    token = args.config['token']

    # Set up HTTP GRAFANA_SESSION with auth header
    GRAFANA_SESSION = rq.Session()
    GRAFANA_SESSION.headers.update({
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    })


def install_grafana_dashboards(args):
    """
    Installs Grafana dashboards from ../5.1/*.json and ../5.0/*.json into:
      - Hammerspace 5.1 and later
      - Hammerspace 5.0
    respectively. If a dashboard already exists, prompts to delete before reinstalling.
    Ensures each dashboard uses the 'Prometheus' data source.
    """

    # Retrieve or create the two folders
    folder_51_id = get_or_create_folder("Hammerspace 5.1 and later")
    folder_50_id = get_or_create_folder("Hammerspace 5.0")

    # 1) Install dashboards in Hammerspace 5.1 and later
    install_dashboards_from_path(args, folder_51_id, "../5.1/*.json")

    # 2) Install dashboards in Hammerspace 5.0
    install_dashboards_from_path(args, folder_50_id, "../5.0/*.json")

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
        print(f"Grafna datasource '{args.datasource_name}' already exists, not modifying")
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
    GRAFANA_PROMETHEUS_UID = resp.json()['uid']

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
            url = 'https://' + url
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
    for anvil_ip in args.config['cluster_ips']:
        asm = AnvilSM()
        asm.auth_creds(anvil_ip)
        nodes = asm.get_nodes()
        cluster = asm.get_cluster()
        clusters.append((cluster, nodes))

    cinfos = []
    for clust, nodes in clusters:
        ci = ClusterInfo()
        cinfos.append(ci)
        ci.anvil_floating_ip = clust[0]['mgmtIps'][0]['address']
        ci.cluster_name = clust[0]['name']
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
            cluster_targets.append(f'{ci.anvil_floating_ip}:{port}')

        static_configs.append({
                'labels': {
                    'node_type': 'clusterip',
                    'instance': ci.cluster_name,
                    'cluster': ci.cluster_name,
                    },
                'targets': cluster_targets, })
    job = {
        'job_name': 'cluster',
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
                anvil_targets.append(f'{anvilip}:{port}')

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
                dsx_targets.append(f'{dsxip}:{port}')

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
    config['grafana_service_account'] = {
        'token': default_token
    }
    config['hosts'] = {
        'grafana_url': 'http://localhost:3000',
        'prometheus_url': 'http://localhost:9090',
    }
    config['cluster_ips'] = {
        'hammerspace1': '1.1.1.1',
        'hammerspace2': '1.1.2.1',
        'comment1': "To configure more than one hammerspace cluster, add multiple hammerspace* entries to this section",
        'comment2': "each pointing to the anvil cluster IP.  If only one cluster is needed remove the excess example lines",
    }

    if not CONFIG_FILE.is_file():
        print(f'WARN: {CONFIG_FILE} not found, generating')
        with CONFIG_FILE.open('w') as fd:
            config.write(fd)

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)

    if config['grafana_service_account']['token'] == default_token:
        print(f'ERR: No grafana service account token found in {CONFIG_FILE}\n')
        print("Please follow the instructions at the below URL to:")
        print("  1) in grafana, generate an admin capable service account")
        print("  2) in grafana, generate an admin capable token in that service account")
        print(f"  3) add the token to the config file {CONFIG_FILE}")
        print("  4) re-run this script")
        print()
        print(f"  {instructions_url}")
        sys.exit(1)

    clusters = []
    for k in config['cluster_ips'].keys():
        if k.lower().startswith('hammerspace'):
            clusters.append(config['cluster_ips'][k])
    ret_config = {
        'token': config['grafana_service_account']['token'],
        'grafana_url': config['hosts']['grafana_url'],
        'prom_url': config['hosts']['prometheus_url'],
        'cluster_ips': clusters,
    }
    return ret_config


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-d', '--dashboards', action='store_true', help="delete grafana dashboards already installed and then install, attaching each to the prometheus data source")
    p.add_argument('-f', '--force', action='store_true', help="Don't prompt about deleting existing grafana dashboards")
    p.add_argument('-p', '--prometheus', action='store_true', help=f"configure prometheus to collect from the cluster(s) specified in {CONFIG_FILE}")
    p.add_argument('-s', '--sample_config', action='store_true', help=f'Generate a sample config.py config file at {CONFIG_FILE}')

    args = p.parse_args()
    args.datasource_name = "Prometheus"

    if not CONFIG_FILE.is_file():
        args.sample_config = True

    if args.sample_config:
        if CONFIG_FILE.is_file():
            p.exit(f'ERROR: Not overwriting existing config file {CONFIG_FILE} with a new sample config file')
        args.config = get_config()
        p.exit()

    args.config = get_config()
    args.prometheus_output = 'prometheus.yml'

    if args.dashboards:
        setup_grafna_session(args)
        setup_prometheus_datasource_in_grafana(args)
        install_grafana_dashboards(args)

    if args.prometheus:
        build_prometheus_config(args)


if __name__ == '__main__':
    main()
