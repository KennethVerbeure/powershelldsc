#!/usr/bin/env python
import socket
import fcntl
import struct
import logging
import os
import json
import argparse

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
    #eg "dc=stack,dc=awingu,dc=com"
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
        "": {
            'dnsIp': args.dns,
            'ntpServer': '0.europe.pool.ntp.org',
        }
    }

    with open(''.join([configs_path, 'network.json']), 'w') as outfile:
        json.dump(network_config, outfile)


def create_domain_config(base_path, configs_path, args):
    domain_pieces = args.domain.split('.')

    domain_config = [{
        "name": domain_pieces[0].upper(),
        "fqdn": args.domain,
        "bindName": args.domain_admin,
        "bindPassword": args.domain_pass,
        "dns": args.dns,
        "hostHeader": "",
        "isAdmin": True,
        "netbios": domain_pieces[0].upper(),
        "userconnector": {
            "ldap": {
                "server": args.domain,
                "baseDn": createBaseDn(domain_pieces)
            },
            "functions": {
                "createBindName": "builtin.create_domain_bind_name",
                "findGroups": "builtin.find_groups_by_member_of"
            }
        }
    }]

    with open(''.join([configs_path, 'domains.json']), 'w') as outfile:
        json.dump(domain_config, outfile)


def create_configs(args):
    base_path = os.path.dirname(os.path.realpath(__file__))
    configs_path = ''.join([base_path, '/config/awingu/azure-arm/'])

    if not os.path.exists(configs_path):
        os.makedirs(configs_path)

        create_network_config(base_path, configs_path, args)
        create_domain_config(base_path, configs_path, args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Deploy an SGO environment')
    parser.add_argument('--dns', type=str, required=True)
    parser.add_argument('--domain', type=str, required=True)
    parser.add_argument('--admin-pass', type=str, required=True)
    parser.add_argument('--domain-admin', type=str, required=True)
    parser.add_argument('--domain-pass', type=str, required=True)
    args = parser.parse_args()

    create_configs(args)

    nodes = [DummyNode('awingu', private_ips=[get_ip_address('eth0')])]

    params = {
        'admin_creds': {
            'username': 'awingu-admin',
            'password': args.admin_pass
        },
        'ssh_patches': False,
        'node_configuration': 'single_node',
        'environment': 'production',
        'repo_url': 'https://repo-pub.awingu.com',
        'invalidate_repo_url': None,
        'apply_changes_after_repo_url_invalidation': True,
        'iaas_stack': 'azure',
        'network_config': False,
        'version': '3.1.0',
        'config_fixtures': 'azure-arm',
        'vm_basename': 'awingu'
    }

    logger.info('Installing Awingu')
    install_via_api(params, None, nodes, '')

    logger.info('Configuring Awingu')
    configure_via_api(params, nodes)

    logger.info('Your Awingu environment is ready')