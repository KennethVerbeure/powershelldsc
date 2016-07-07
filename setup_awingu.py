#!/usr/bin/env python
import socket
import fcntl
import struct
import logging
import os
import json
import argparse
import requests

from shutil import copyfile

from api_installer import install_via_api, configure_via_api

logger = logging.getLogger('deploy_awingu')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('deploy_awingu.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


class DummyNode(object):

    def __init__(self, name, private_ips):
        self.name = name
        self.private_ips = private_ips


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def createBaseDn(domain_pieces):
    #eg 'dc=stack,dc=awingu,dc=com'
    baseDn = ''
    first = True

    for piece in domain_pieces:
        if first:
            first = False
            baseDn += 'dc=%s' % piece
        else:
            baseDn += ',dc=%s' % piece

    return baseDn


def create_network_config(base_path, configs_path, args):
    network_config = {
        '': {
            'dnsIp': args.dns,
            'ntpServer': '0.europe.pool.ntp.org',
        }
    }

    with open(''.join([configs_path, 'network.json']), 'w') as outfile:
        json.dump(network_config, outfile)


def create_domain_config(base_path, configs_path, args):
    domain_pieces = args.domain.split('.')
    domain_name = domain_pieces[0].upper()

    domain_config = [{
        'name': domain_name,
        'fqdn': args.domain,
        'bindName': args.domain_admin,
        'bindPassword': args.domain_pass,
        'dns': args.dns,
        'hostHeader': '',
        'isAdmin': True,
        'netbios': domain_name,
        'userconnector': {
            'ldap': {
                'server': args.domain,
                'baseDn': createBaseDn(domain_pieces)
            },
            'functions': {
                'createBindName': 'builtin.create_domain_bind_name',
                'findGroups': 'builtin.find_groups_by_member_of'
            }
        }
    }]

    with open(''.join([configs_path, 'domains.json']), 'w') as outfile:
        json.dump(domain_config, outfile)

    create_usergroups_config(base_path, configs_path, domain_name)
    create_labels_config(base_path, configs_path, domain_name)
    create_drives_config(base_path, configs_path, args, domain_name)
    create_apps_config(base_path, configs_path, domain_name)
    create_appserver_config(base_path, configs_path, domain_name)


def create_usergroups_config(base_path, configs_path, domain_name):
    usergroups_config = {}
    usergroups_config[domain_name] = {
        'white_list': [
            {
                'isSignInWhiteListed': False,
                'name': 'Administrators'
            }
        ],
        'flags': {
            'Administrators': [
                'admin'
            ]
        }
    }

    with open(''.join([configs_path, 'usergroups.json']), 'w') as outfile:
        json.dump(usergroups_config, outfile)


def create_labels_config(base_path, configs_path, domain_name):
    labels_config = {}
    labels_config[domain_name] = [
        {
            'key': 'servergroup',
            'value': 'win2012'
        }
    ]

    with open(''.join([configs_path, 'labels.json']), 'w') as outfile:
        json.dump(labels_config, outfile)


def create_drives_config(base_path, configs_path, args, domain_name):
    ad_fqdn = '%s.%s' % (args.ad_machine_name, args.domain)
    drives_config = {}
    drives_config[domain_name] = [
        {
            'authToken': '',
            'description': 'Home Drive via CIFS',
            'url': 'smb://%s/Users/<username>/documents' % ad_fqdn,
            'labels': [],
            'userLabels': [
                {
                    'key': 'all',
                    'value': ''
                }
            ],
            'unc': '\\\\%s\\Users\\<username>\\documents\\<document>' %
                args.ad_machine_name,
            'useDomain': False,
            'backend': 'CIFS',
            'name': 'Home Drive (CIFS)'
        }
    ]

    with open(''.join([configs_path, 'drives.json']), 'w') as outfile:
        json.dump(drives_config, outfile)


def create_apps_config(base_path, configs_path, domain_name):
    apps_config = {}
    apps_config[domain_name] = [
        {
            'protocol': 'REMOTE-APP',
            'description': 'Notepad running on Application Server 2012',
            'serverLabels': [
                {
                    'key': 'servergroup',
                    'value': 'win2012'
                }
            ],
            'labels': [],
            'workingFolder': '',
            'userLabels': [
                {
                    'key': 'all',
                    'value': ''

                }
            ],
            'command': 'NOTEPAD',
            'mediaTypes': [
                'text/plain'
            ],
            'icon': 'notepad.png',
            'supportsUnicodeKbd': True,
            'categories': [],
            'name': 'Notepad'
        },
        {
            'protocol': 'REMOTE-APP',
            'description': 'Remote desktop connection running on ' +
                'Application Server 2012',
            'serverLabels': [
                {
                    'key': 'servergroup',
                    'value': 'win2012'
                }
            ],
            'labels': [],
            'workingFolder': '',
            'userLabels': [
                {
                    'key': 'admin',
                    'value': ''
                }
            ],
            'command': 'MSTSC',
            'mediaTypes': [],
            'icon': 'mstsc.png',
            'supportsUnicodeKbd': True,
            'categories': [],
            'name': 'AD Remote desktop'
        }
    ]

    with open(''.join([configs_path, 'apps.json']), 'w') as outfile:
        json.dump(apps_config, outfile)


def create_appserver_config(base_path, configs_path, domain_name):
    appserver_config = {}
    appserver_config[domain_name] = [
        {
            'description': 'description',
            'labels': [
                {
                    'key': 'servergroup',
                    'value': 'win2012'

                }
            ],
            'enabled': True,
            'host': '',
            'maxConnections': 1000,
            'port': 3389,
            'name': ''
        }
    ]

    with open(''.join([configs_path, 'appservers.json']), 'w') as outfile:
        json.dump(appserver_config, outfile)


def create_configs(args):
    base_path = os.path.dirname(os.path.realpath(__file__))
    configs_path = ''.join([base_path, '/config/awingu/azure-arm/'])

    if not os.path.exists(configs_path):
        os.makedirs(configs_path)

        create_network_config(base_path, configs_path, args)
        create_domain_config(base_path, configs_path, args)


def setup_icons():
    base_path = os.path.dirname(os.path.realpath(__file__))
    icons_path = ''.join([base_path, '/icons/'])

    if not os.path.exists(icons_path):
        os.makedirs(icons_path)

        copyfile('%s/notepad.png' % base_path, '%s/notepad.png' % icons_path)
        copyfile('%s/mstsc.png' % base_path, '%s/mstsc.png' % icons_path)


def send_email_to_awingu(email):
    url = 'https://api.awingu.com/api/users/createzoholead'

    try:
        requests.post(url=url, timeout=10, data={
            'email': args.email,
            'company': 'Awingu Greenfield'
        })
    except:
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Deploy an SGO environment')
    parser.add_argument('--dns', type=str, required=True)
    parser.add_argument('--domain', type=str, required=True)
    parser.add_argument('--admin-pass', type=str, required=True)
    parser.add_argument('--domain-admin', type=str, required=True)
    parser.add_argument('--domain-pass', type=str, required=True)
    parser.add_argument('--ad-machine-name', type=str, required=True)
    parser.add_argument('--email', type=str, required=True)
    args = parser.parse_args()

    create_configs(args)
    setup_icons()

    nodes = [DummyNode('awingu', private_ips=[get_ip_address('eth0')])]

    params = {
        'admin_creds': {
            'username': 'awingu-admin',
            'password': args.admin_pass
        },
        'node_configuration': 'single_node',
        'environment': 'production',
        'repo_url': 'https://repo-preview.awingu.com',
        'invalidate_repo_url': None,
        'apply_changes_after_repo_url_invalidation': True,
        'iaas_stack': 'azure',
        'version': '3.2.0',
        'config_fixtures': 'azure-arm',
        'vm_basename': 'awingu',
        'ssh_patches': False,
        'import_appservers': True,
        'import_appserver_blacklist': [
            '%s.%s' % (args.ad_machine_name, args.domain)
        ]
    }

    logger.info('Installing Awingu')
    install_via_api(params, None, nodes, '')

    logger.info('Configuring Awingu')
    configure_via_api(params, nodes)
    send_email_to_awingu(args)
    logger.info('Your Awingu environment is ready')
