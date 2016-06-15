#!/usr/bin/env python

import copy
import pprint
import json
import os
import logging
import re
import time
import requests


SERVICES = ['dns', 'database', 'mq', 'memcache', 'frontend', 'worker', 'proxy',
            'indexer', 'metering', 'rdpgw']

SERVICE_CONFIGS = {
    'single_node': 'single_node',
    'multi_node_200users': {
        'dns': ['node1', 'node2'],
        'database': ['node1'],
        'mq': ['node1', 'node2'],
        'memcache': ['node1', 'node2'],
        'frontend': ['node1', 'node2'],
        'worker': ['node1', 'node2'],
        'proxy': ['node1', 'node2'],
        'indexer': ['node1'],
        'metering': ['node1', 'node2'],
        'rdpgw': ['node1', 'node2']},
    'multi_node_manual': 'manual'}

DATABASES = {'frontendWeb': 'frontendweb',
             'appGateway': 'appgw',
             'graphiteWeb': 'graphiteweb',
             'metering': 'metering'}

KEEP_REPOSERVER_VERSION = re.compile(r'v?[0-9]+\.[0-9]+\.[0-9]+'
                                     r'(\.[0-9]+(-.*)?)?')

API_ADMIN_CREDS = {'username': 'admin',
                   'password': 'rooter1234'}

REQUEST_TYPES = ['GET', 'PUT', 'HEAD', 'POST', 'DELETE']

URI_ID_REX = re.compile(r'/api/\w*/(?P<id>\d+)/')


logger = logging.getLogger('deploy_awingu')

api_logger = logging.getLogger('api_calls')
api_logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('api_calls.log', mode='w')
fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
api_logger.addHandler(fh)


def log_headers(lg, headers):
    lg.debug('Headers:')
    for line in pprint.pformat(dict(headers), width=1).splitlines():
        lg.debug('%s%s', (9 * ' '), line)


def log_data(lg, data):
    if data:
        lg.debug('Data:')
        try:
            data_dict = json.loads(data)
            for line in pprint.pformat(data_dict, width=1).splitlines():
                lg.debug('%s%s', (6 * ' '), line)
        except:
            lg.debug('%s%s', (6 * ' '), data)
    else:
        return


def api_call(request_type, session, url, log=True, raise_for_status=True,
             data=None, headers=None, **kwargs):
    if request_type.upper() not in REQUEST_TYPES:
        raise NotImplementedError('Request of type %s is not implemented' %
                                  request_type)

    response = _api_call(request_type, session, url, log, data, headers,
                         **kwargs)
    # Retry if we get a 429 Client Error: too many requests
    if response.status_code == 429:
        logger.warning(
            'Due to HTTP error %s (%s), we will wait 1 minute and retry',
            response.status_code, response.reason)
        time.sleep(60)
        response = _api_call(request_type, session, url, log, data, headers,
                             **kwargs)

    if raise_for_status:
        response.raise_for_status()

    return response


def _api_call(request_type, session, url, log, data, headers, **kwargs):
    call = getattr(session, request_type.lower())
    response = call(url, data=data, headers=headers, **kwargs)

    if log:
        api_logger.debug('%sREQUEST%s', (40 * '-'), (40 * '-'))
        api_logger.debug('%s to %s', request_type.upper(), url)
        headers_to_log = dict()
        headers_to_log.update(session.headers)
        headers_to_log.update(headers if headers else {})
        log_headers(api_logger, headers_to_log)
        log_data(api_logger, data)

        api_logger.debug('%sRESPONSE%s', (40 * '-'), (40 * '-'))
        log_headers(api_logger, response.headers)
        log_data(api_logger, response.text)
        api_logger.debug('\n%s\n', 80 * '=')

    return response


def update_dict(original, updates):
    for key, value in updates.iteritems():
        if isinstance(value, dict) and isinstance(original.get(key), dict):
            update_dict(original[key], value)
        else:
            original[key] = value


def patch_appliance(frontend_ips, key_filename, version, params):
    import fabric.context_managers, fabfile

    for frontend_ip in frontend_ips:
        with fabric.context_managers.settings(host_string=frontend_ip,
                                              user='root',
                                              key_filename=key_filename):
            if params.get('license_package_url'):
                fabfile.add_license_verification_key(
                    params['license_package_url'])

            p = re.compile('^awingu-appliance-%s( |-20).*' % version)
            if not p.match(params.get('vm_template', '')):
                fabfile.edit_version_file(version)


def generate_server_list(params):
    '''
    This function can be used by deployer functions
    '''
    base_name = str(params['vm_basename'])
    node_config_name = params.get('node_configuration', 'single_node')

    try:
        service_config = SERVICE_CONFIGS[node_config_name]
    except KeyError:
        raise KeyError(
            'SGO only defined for following configurations: %s' %
            SERVICE_CONFIGS.keys())

    if service_config == 'single_node':
        return [base_name]

    if service_config == 'manual':
        service_config = params['manual_service_config']

    for service in SERVICES:
        if service not in service_config:
            raise KeyError(
                'Service "%s" missing in service config' % service)
        elif service != 'database' and not service_config[service]:
            raise RuntimeError(
                'Service "%s" has no node assigned to it' % service)

    servers_set = set()
    for service, suffixes in service_config.iteritems():
        servers_set.update(set([base_name + '-' + suffix
                                for suffix in suffixes]))

    first_server = base_name + '-' + service_config['proxy'][0]
    servers_set.remove(first_server)
    hostname_list = [first_server] + list(servers_set)
    return hostname_list


def build_service_config(params, nodes):
    base_name = str(params['vm_basename'])
    node_config_name = params.get('node_configuration', 'single_node')
    service_config = SERVICE_CONFIGS[node_config_name]

    servers = {}
    if service_config == 'single_node':
        assert(len(nodes) == 1)
        assert(base_name == nodes[0].name)
        servers['roster'] = {base_name: '127.0.0.1'}
        servers['services'] = {service: [base_name] for service in SERVICES}
        # TODO: HACK FOR EXTERNAL CLOUDS
        if params['iaas_stack'] in ['openstack', 'azure']:
            frontend_ips = [nodes[0].private_ips[0]]
        else:
            frontend_ips = [nodes[0].public_ips[0]]
        servers['appliances'] = [{"hostname": base_name,
                                  "ip": nodes[0].private_ips[0],
                                  "services": SERVICES}]

    else:
        if service_config == 'manual':
            service_config = params['manual_service_config']
        servers['roster'] = {node.name: node.private_ips[0]
                             for node in nodes}
        servers['services'] = {service: [base_name + '-' + suffix
                                         for suffix in suffixes]
                               for service, suffixes
                               in service_config.iteritems()}
        frontend_ips = [servers['roster'][node]
                        for node in servers['services']['frontend']]

        # TODO: HACK FOR EXTERNAL CLOUDS
        if params['iaas_stack'] not in ['openstack', 'azure']:
            frontend_nodes = [node for node in nodes if node.name in
                              servers['services']['frontend']]
            frontend_ips = [node.public_ips[0] for node in frontend_nodes]

        servers['appliances'] = [{"hostname": node.name,
                                  "ip": node.private_ips[0],
                                  "services":
                                  [k for k in service_config.keys() if
                                   node.name.replace(base_name + '-', '')
                                   in service_config[k]]}
                                 for node in nodes]

    return servers, frontend_ips


def install_via_api(params, iaas_config, nodes, pub_ip):
    node_config_name = params.get('node_configuration', 'single_node')
    version = params['version']

    network_config = get_component_config(params['config_fixtures'],
                                          'network',
                                          params.get('extra_config'))['']

    admin_creds = params.get('admin_creds', API_ADMIN_CREDS)

    installer_config = {
        'version_number': version,
        'config': {
            'eula': {'accepted': True},
            'environment': {
                'managementUser': {
                    'username': admin_creds['username'],
                    'password': admin_creds['password'],
                    'confirmed_password': admin_creds['password'],
                },
                'partner': {
                    'name': 'Partner Inc.',
                    'addressLine1': 'Partner Street 007',
                    'addressLine2': None,
                    'city': 'Partner City',
                    'location': 'Partner Region',
                    'postalCode': 'P007',
                    'country': 'Belgium',
                    'phoneNumber': None},
                'accountManager': {
                    'name': 'Mr. Account Manager',
                    'addressLine1': None,
                    'addressLine2': None,
                    'city': None,
                    'location': None,
                    'postalCode': None,
                    'country': None,
                    'phoneNumber': None},
            },
            'network': {
                'repo': params['repo_url'],
                'ntp': network_config['ntpServer'],
                'dns': network_config['dnsIp'],
                'httpProxy': '',
            },
            'features': {'common': {'httpProxy': False}},
        }
    }

    servers, frontend_ips = build_service_config(params, nodes)
    installer_config['config']['appliances'] = servers['appliances']
    frontend_ip = frontend_ips[0]

    custom_sls = {
        'environment': params.get('environment', 'production'),
        'hosts': {
            '10.147.128.173': 'build.awingu.com',
            '10.147.128.131': 'build-2-3.awingu.com',
            '10.147.128.171': 'build-dev.awingu.com'},
    }

    databases = params.get('external_databases', {})
    if databases == {}:
        installer_config['config']['features']['common'
                                               ]['externalDatabase'] = False
        if node_config_name == 'single_node':
            installer_config['config']['database'] = {
                db_key: None for db_key in DATABASES}
        else:
            db_host = servers['services']['database'][0]
            installer_config['config']['database'] = {
                db_key: 'postgresql://user:pass@%s:5432/%s' % (
                    db_host, DATABASES[db_key])
                for db_key in DATABASES}
    else:
        installer_config['config']['features']['common'
                                               ]['externalDatabase'] = True
        installer_config['config']['database'] = databases

    if params.get('ssh_patches', True) is True:
        import fabric.context_managers, fabfile
        key_filename = os.path.expanduser('~/.ssh/%s.pem' %
                                          iaas_config['vm_keyname'])
        intervention_key = os.path.expanduser('~/.ssh/intervention_dev.pem')

        # Patch the hostfile on all nodes (to spare the layer 3 agent
        # on prostack)
        for node in nodes:
            # TODO: HACK FOR EXTERNAL CLOUDS
            if params['iaas_stack'] != 'openstack':
                host_string = node.public_ips[0]
            else:
                host_string = node.private_ips[0]
            with fabric.context_managers.settings(host_string=host_string,
                                                  user='root',
                                                  key_filename=key_filename):
                fabfile.add_to_hostfile(custom_sls['hosts'])

        # Patches for the frontend nodes(license certificate and versions file)
        patch_appliance(frontend_ips, key_filename, version, params)

        # Patches in custom.sls(only on the node where we start the installer)
        with fabric.context_managers.settings(host_string=frontend_ip,
                                              user='root',
                                              key_filename=key_filename):
            fabfile.write_custom_sls(custom_sls)

    timeout = 180
    start_time = time.time()
    logger.info('Waiting for max. %s seconds '
                'for installer API to be available', timeout)
    api_logger.info('Every 5s: GET to http://%s:8080 for max. %ds',
                    frontend_ip,
                    timeout)
    while time.time() - start_time <= timeout:
        try:
            requests.get(url='http://%s:8080' % frontend_ip)
        except requests.exceptions.ConnectionError:
            time.sleep(5)
        else:
            break
    else:
        raise RuntimeError(
            'Installer API not available after %s seconds' % timeout)

    time.sleep(5)
    logger.info('Sending config to API on %s:\n%s',
                frontend_ip, json.dumps(installer_config, indent=4))
    s = requests.Session()

    headers = {'Accept': 'application/vnd.sgo.update',
               'Content-Type': 'application/vnd.sgo.update'}
    api_call('post', s,
             url='http://%s:8080/smc-api/updates/' % frontend_ip,
             headers=headers, data=json.dumps(installer_config))

    max_errors = 10
    timeout = (40 + 10 * len(nodes)) * 60

    url = 'http://%s:8080/smc-api/updates/latest/' % frontend_ip
    wait_for_smc(s, url, max_errors, timeout, 'installation', use_410=True)

    if (params.get('ssh_patches', True) is True and
        SERVICE_CONFIGS[node_config_name] != 'single_node'):
        with fabric.context_managers.settings(host_string=pub_ip,
                                              user='root',
                                              key_filename=intervention_key):
            logger.info('Install Tmuxifier on proxy node')
            fabfile.install_tmuxifier(servers['roster'].keys(),
                                      servers['services'])


def get_user_groups(session, base_url, usergroups_uri, key=None):
    '''
    @param session: the session on which to make the request
    @type session: requests.Session

    @param base_url: the URL to make the request to
    @type base_url: string

    @param usergroups_uri: the URI for of the usergroups of the domain
    @type usergroups_uri: string

    @param key: specific key to retrieve from the usergroups['objects'].
                Set to none to retrieve all
    @type key: string
    '''

    logger.info('      --> Get user groups')
    usergroups = api_call('get', session,
                          '%s%s' % (base_url, usergroups_uri)).json()
    if key:
        existing_usergroups = [ug[key] for ug in usergroups['objects']]
    else:
        existing_usergroups = usergroups['objects']

    return existing_usergroups


def make_session(ip, port=None, login=True, creds=API_ADMIN_CREDS):
    base_url = 'http://%s' % ip
    base_url = '%s:%d' % (base_url, port) if port else base_url
    sess = requests.Session()
    logger.info('Initial GET to %s', base_url)
    api_call('get', sess, base_url)

    if login:
        headers = {'Content-Type': 'application/json'}
        logger.info('POST to %s/api/sessions/', base_url)
        sess.post(base_url + '/api/sessions/', headers=headers,
                  data=json.dumps(creds))

    sess.headers.update({'Accept': '',
                         'X-csrftoken': sess.cookies.get('csrftoken')})

    return sess, base_url


def set_usergroup_flags(usergroups_config, session, base_url, usergroups_uri):
    logger.info('      --> Set usergroup flags')

    usergroups = get_user_groups(session, base_url, usergroups_uri)
    for ug_name, flags_to_set in usergroups_config['flags'].iteritems():
        existing_ugs = [ug for ug in usergroups if ug['name'] == ug_name]
        if len(existing_ugs) != 1:
            raise RuntimeError('Found %d groups named %s, expected exactly 1' %
                               (len(existing_ugs), ug_name))
        existing_ug = existing_ugs[0]

        logger.info('      --> Setting flags for %s: %s', ug_name,
                    flags_to_set)
        for flag in flags_to_set:
            if flag not in [x['key'] for x in existing_ug['userLabels']]:
                r = session.post('%s%suserlabels/' % (base_url,
                                                      existing_ug['uri']),
                                 data=json.dumps({'key': flag}))
                r.raise_for_status()


def _search_dict_for_uris(d):
    result = []
    for key, value in d.iteritems():
        if isinstance(value, dict):
            result += _search_dict_for_uris(value)
        if 'uri' in key.lower():
            result.append({key: value})

    return result


def _get_nested_smc_uris(sess, base_url, smc_uris):
    retval = {}
    for uri in smc_uris.values():
        resp = api_call('get', sess, '%s%s' % (base_url, uri),
                        raise_for_status=False)
        if not resp.ok:
            logger.warning('Failed to get %s%s (error %s)',
                           base_url, uri, resp.status_code)
            continue
        response = resp.json()
        if not isinstance(response, dict):
            continue
        result = _search_dict_for_uris(response)
        for d in result:
            for key, value in d.iteritems():
                if key != 'uri':
                    retval[key] = value

    return retval


def configure_multi_item_component(sess, base_url, uri, component_config):
    for domain_name, multi_item_config in component_config.iteritems():
        select_managing_domain(sess, base_url, domain_name)
        if not isinstance(multi_item_config, list):
            multi_item_config = [multi_item_config]
        for component_item in multi_item_config:
            created_object = api_call(
                'post', sess, '%s%s' % (base_url, uri),
                data=json.dumps(component_item),
                headers={'Content-Type': 'application/json'}).json()

            # https://jira.awingu.com/browse/CD-3187
            for potential_key in ['uri', 'resourceUri']:
                object_uri = created_object.get(potential_key)
                if object_uri:
                    match = re.match(URI_ID_REX, object_uri)
                    created_object_id = match.groupdict()['id']
                    break
            else:
                created_object_id = created_object['id']

            configure_component_links(component_item, sess, base_url, uri,
                                      created_object, created_object_id)


def configure_component_links(component_item, sess, base_url, uri,
                              created_object, created_object_id):
    if component_item.get('labels'):
        add_labels(sess, base_url, uri, component_item, created_object_id)
    if component_item.get('serverLabels'):
        add_server_labels(sess, base_url, uri, component_item,
                          created_object_id)
    if component_item.get('userLabels'):
        add_user_labels(sess, base_url, uri, component_item, created_object_id)
    if component_item.get('categories'):
        add_categories(sess, base_url, uri, component_item, created_object_id)
    if component_item.get('mediaTypes'):
        add_media_types(sess, base_url, uri, component_item, created_object_id)
    if component_item.get('icon'):
        add_icon(sess, base_url, uri, component_item, created_object,
                 created_object_id)


def add_icon(sess, base_url, uri, component_item, created_app, app_id):
    filename = component_item['icon']

    local_file = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              'icons', filename)

    with open(local_file, 'rb') as fp:
        r = api_call('POST', sess, '%s/api/appicon/' % base_url,
                     files=[('file', (filename, fp, 'image/png'))])

    created_app['icon'] = r.json()['uri']

    api_call('PUT', sess, '%s%s%s/' % (base_url, uri, app_id),
             data=json.dumps(created_app),
             headers={'Content-Type': 'application/json'})


def add_media_types(sess, base_url, uri, component_item, app_id):
    for media_type in component_item['mediaTypes']:
        existing_mediatype = get_existing_object(sess, base_url,
                                                 '/api/mediatypes',
                                                 media_type, 'contentType')
        api_call('post', sess, '%s%s%s/mediatypes/' % (base_url, uri, app_id),
                 data=json.dumps({"mediaTypeUri": existing_mediatype['uri']}),
                 headers={'Content-Type': 'application/json'})


def get_existing_object(sess, base_url, uri, object_name, criterium):
    existing_objects = api_call('get', sess, '%s%s' % (base_url, uri)).json()
    matched_objects = filter(lambda x: x.get(criterium) == object_name,
                             existing_objects['objects'])
    if not matched_objects:
        raise RuntimeError('Object %s does not exist' % object_name)

    return matched_objects[0]


def add_categories(sess, base_url, uri, component_item, app_id):
    for category in component_item['categories']:
        existing_category = get_existing_object(sess, base_url,
                                                '/api/categories',
                                                category, 'name')
        api_call('post', sess, '%s%s%s/categories/' % (base_url, uri, app_id),
                 data=json.dumps({"categoryUri": existing_category['uri']}),
                 headers={'Content-Type': 'application/json'})


def add_user_labels(sess, base_url, uri, component_item, object_id):
    for label in component_item['userLabels']:
        lbl = get_existing_label(sess, base_url, label)
        api_call('post', sess,
                 '%s%s%s/userlabels/' % (base_url, uri, object_id),
                 data=json.dumps({"labelUri": lbl['uri']}),
                 headers={'Content-Type': 'application/json'})


def get_existing_label(sess, base_url, label):
    existing_labels = api_call('get', sess, '%s/api/labels' % base_url).json()
    matched_labels = filter(lambda x: x.get('key') == label['key'] and
                            x.get('value') == label['value'],
                            existing_labels['objects'])

    if not matched_labels:
        raise RuntimeError('Label %s does not exist' % label)

    if len(matched_labels) > 1:
        matched_labels = filter(
            lambda x: x.get('domain') != '', matched_labels)

    if len(matched_labels) != 1:
        raise RuntimeError('This should never happen')

    return matched_labels[0]


def add_server_labels(sess, base_url, uri, component_item, object_id):
    for label in component_item['serverLabels']:
        lbl = get_existing_label(sess, base_url, label)
        api_call('post', sess,
                 '%s%s%s/serverlabels/' % (base_url, uri, object_id),
                 data=json.dumps({'labelUri': lbl['uri']}),
                 headers={'Content-Type': 'application/json'})


def add_labels(sess, base_url, uri, component_item, object_id):
    for label in component_item['labels']:
        lbl = get_existing_label(sess, base_url, label)
        api_call('post', sess,
                 '%s%s%s/labels/' % (base_url, uri, object_id),
                 data=json.dumps({'labelUri': lbl['uri']}),
                 headers={'Content-Type': 'application/json'})


def set_login_text(sess, base_url, smc_uris, params):
    logger.info('  --> Setting login text')
    branding_uri = '%s%s' % (base_url, smc_uris['brandingUri'])
    branding = api_call('get', sess, branding_uri).json()
    branding['loginFooter'] = params['vm_basename']
    api_call('put', sess, branding_uri, data=json.dumps(branding))


def _make_set_from_labels(labels):
    return {(label['key'], label['value']) for label in labels}


def configure_features(sess, base_url, uri, component_config):
    for domain_name, features_config in component_config.iteritems():
        select_managing_domain(sess, base_url, domain_name)
        r = api_call('get', sess, '%s%s' % (base_url, uri))
        features = r.json()['objects']
        for feature_name, config_labels in features_config.iteritems():
            current_labels, feature_labels_uri = [
                (feature['labels'], feature['featureLabelsUri'])
                for feature in features if feature['name'] == feature_name][0]
            current_labels_set = _make_set_from_labels(current_labels)
            config_labels_set = _make_set_from_labels(config_labels)

            # Adding new labels
            for key, value in config_labels_set - current_labels_set:
                new_label = {'key': key, 'value': value}
                label_uri = get_existing_label(sess, base_url,
                                               new_label)['uri']
                api_call('post', sess, '%s%s' % (base_url, feature_labels_uri),
                         data=json.dumps({'labelUri': label_uri}))

            # Removing unwished labels
            for key, value in current_labels_set - config_labels_set:
                label_uri = [
                    label['uri'] for label in current_labels
                    if (label['key'], label['value']) == (key, value)][0]
                api_call('delete', sess, '%s%s' % (base_url, label_uri))


def configure_usergroups(sess, base_url, component_config, smc_uris):
    for domain_name, usergroup_config in component_config.iteritems():
        select_managing_domain(sess, base_url, domain_name)
        r = api_call('get', sess, '%s%s' % (base_url, smc_uris['domainsUri']))
        domain = [d for d in r.json()['objects']
                  if d['name'] == domain_name][0]
        userconnector_uri = domain['userconnectorUri']

        userconnector = api_call('get', sess,
                                 '%s%s' % (base_url, userconnector_uri)).json()
        usergroups_uri = userconnector['ldap']['userGroupsUri']

        for usergroup in usergroup_config.get('white_list', []):
            api_call('post', sess, '%s%s' % (base_url, usergroups_uri),
                     data=json.dumps(usergroup))
        set_usergroup_flags(usergroup_config, sess, base_url, usergroups_uri)


def configure_domains(sess, base_url, uri, component_config):
    for domain_config in component_config:
        userconnector_config = domain_config.pop('userconnector')
        domain = api_call('post', sess, '%s%s' % (base_url, uri),
                          data=json.dumps(domain_config)).json()
        userconnector_uri = domain['userconnectorUri']

        select_managing_domain(sess, base_url, domain['name'])
        userconnector = api_call('put', sess,
                                 '%s%s' % (base_url, userconnector_uri),
                                 data=json.dumps({})).json()

        update_dict(userconnector, userconnector_config)
        api_call('put', sess, '%s%s' % (base_url, userconnector_uri),
                 data=json.dumps(userconnector))


def select_managing_domain(sess, base_url, domain_name):
    api_call('put', sess, '%s/api/sessions/' % base_url,
             data=json.dumps({"managingDomain": domain_name}))


def configure_smcapi_component(sess, base_url, uri, component_config,
                               pop_uri=True):
    for domain_name, smcapi_config in component_config.iteritems():
        select_managing_domain(sess, base_url, domain_name)
        current_config = api_call('get', sess, '%s%s' % (base_url, uri)).json()
        new_config = copy.deepcopy(current_config)
        new_config.update(smcapi_config)
        if new_config == current_config:
            continue
        if pop_uri:
            current_config.pop('uri')
        api_call('put', sess, '%s%s' % (base_url, uri),
                 data=json.dumps(new_config))


def import_appservers(sess, base_url, uri, component_config, smc_uris, params):
    domains = component_config.keys()
    appservers_config = {}

    for domain_name in domains:
        domain_name = str(domain_name)
        appservers_config[domain_name] = []
        appserver_template = component_config[domain_name][0]

        domain = api_call('get', sess, '%s%s%s' %
            (base_url, smc_uris['domainsUri'], domain_name)).json()

        appservers = api_call('get', sess, '%s%s' %
            (base_url, domain['appServersUri'])).json()['objects']

        for appserver in appservers:
            if (appserver['hostName'].lower() in
                params['import_appserver_blacklist']):
                continue

            appserver_config = copy.deepcopy(appserver_template)
            appserver_config['host'] = appserver['hostName']
            appserver_config['name'] = appserver['name']
            appserver_config['description'] = appserver['name']
            appservers_config[domain_name].append(appserver_config)

    configure_multi_item_component(sess, base_url, uri, appservers_config)


def configure_component(component, component_config, sess, base_url,
                        uri, smc_uris, params):
    logger.info('  --> Configuring %s', component)
    if component == 'domains':
        configure_domains(sess, base_url, uri, component_config)
    elif component == 'features':
        configure_features(sess, base_url, uri, component_config)
    elif component == 'usergroups':
        configure_usergroups(sess, base_url, component_config, smc_uris)
    elif component == 'appservers' and params.get('import_appservers'):
        import_appservers(sess, base_url, uri, component_config, smc_uris,
                          params)
    elif uri.startswith('/smc-api'):
        configure_smcapi_component(sess, base_url, uri, component_config)
    else:
        configure_multi_item_component(sess, base_url, uri, component_config)


def configure_smc(sess, base_url, smc_uris, params):
    priority_components = ['domains', 'usergroups', 'labels', 'appservers',
                           'categories']
    smc_components = {key.replace('Uri', '').lower(): uri
                      for key, uri in smc_uris.iteritems()}
    components = priority_components + [c for c in smc_components
                                        if c not in priority_components]

    for component in components:
        uri = smc_components.get(component)
        component_config = get_component_config(params['config_fixtures'],
                                                component,
                                                params.get('extra_config'))
        if component_config:
            configure_component(component, component_config, sess, base_url,
                                uri, smc_uris, params)


def invalidate_reposerver(sess, base_url, smc_uris):
    logger.info('  --> Invalidating reposerver URL')
    network_uri = '%s%s' % (base_url, smc_uris['networkUri'])
    network = api_call('get', sess, network_uri).json()
    invalid_url = 'http://notbuild.awingu.com'
    if network['repoUrl'] != invalid_url:
        network['repoUrl'] = 'http://notbuild.awingu.com'
        network.pop('uri')
        api_call('put', sess, network_uri, data=json.dumps(network))


def configure_via_api(params, nodes):
    # TODO: HACK FOR EXTERNAL CLOUDS
    if params['iaas_stack'] in ['openstack', 'azure']:
        proxy_ip = nodes[0].private_ips[0]
    else:
        proxy_ip = nodes[0].public_ips[0]

    timeout = 120
    start_time = time.time()
    logger.info('Waiting for max. %s seconds to be able to sign-in', timeout)
    while time.time() - start_time <= timeout:
        try:
            admin_creds = params.get('admin_creds', API_ADMIN_CREDS)
            sess, base_url = make_session(proxy_ip, creds=admin_creds)
        except requests.exceptions.HTTPError as e:
            logger.warning('Ignore error during sign-in: %s', e)
            time.sleep(10)
        else:
            break
    else:
        raise RuntimeError("Still can't sign in after %s seconds" % timeout)

    smc_uris = get_smc_uris(sess, base_url, nested=True)

    logger.info('Applying configuration')
    set_login_text(sess, base_url, smc_uris, params)
    configure_smc(sess, base_url, smc_uris, params)
    apply_changes_needed = is_apply_changes_needed(sess, base_url, smc_uris)

    invalidate_repo_url = params.get('invalidate_repo_url', None)
    if invalidate_repo_url is True or \
            (invalidate_repo_url is None and
             not KEEP_REPOSERVER_VERSION.match(params['version'])):
        invalidate_reposerver(sess, base_url, smc_uris)
        if params.get('apply_changes_after_repo_url_invalidation', False):
            apply_changes_needed = is_apply_changes_needed(sess, base_url,
                                                           smc_uris)

    if apply_changes_needed:
        apply_changes(sess, base_url, smc_uris, len(nodes))


def is_apply_changes_needed(session, base_url, smc_uris):
    logger.info('Checking if apply changes is needed')
    latest_update_url = '%s%s' % (base_url, smc_uris['latestUpdateUri'])
    latest_update = api_call('get', session, latest_update_url).json()
    latest_history_url = '%s%s' % (base_url, smc_uris['latestHistoryUri'])
    latest_history = api_call('get', session, latest_history_url).json()
    apply_changes_needed = latest_history['date'] > latest_update['end']
    logger.info('  --> Apply changes is %s',
                {True: 'needed', False: 'not needed'}[apply_changes_needed])
    return apply_changes_needed


def apply_changes(session, base_url, smc_uris, nr_of_nodes):
    logger.info('Applying changes')
    api_call('post', session, '%s%s' % (base_url, smc_uris['updatesUri']),
             data=json.dumps({}))

    max_errors = 10
    timeout = (10 + 5 * nr_of_nodes) * 60
    update_url = '%s%s' % (base_url, smc_uris['latestUpdateUri'])
    logger.info('Waiting for configuration on %s', update_url)
    wait_for_smc(session, update_url, max_errors, timeout, 'configuration')


def wait_for_smc(session, url, max_errors, timeout, action, use_410=False):
    '''
    Wait for the server to finish an action

    @param session: HTTP session
    @type session: requests.Session

    @param url: URL to check the SMC api
    @type url: string

    @param max_errors: maximum errors to accept
    @type max_errors: int

    @param timeout: how long to wait
    @type timeout: int

    @param action: which action to wait for (used for logging)
    @type action: string

    @param use_410: use HTTP 410 error (GONE) to consider the SMC as finished
    @type use_410: bool

    @returns server response on success
    '''

    errors = 0
    start_time = time.time()
    logger.info('Waiting for max. %s minutes for %s to finish' %
                (timeout / 60, action))
    api_logger.info('Every 5s: GET to %s for max. %ds', url, timeout)
    while time.time() - start_time <= timeout:
        if errors >= max_errors:
            raise RuntimeError(
                'Getting status of %s failed %s times' % (action, errors))
        time.sleep(5)
        try:
            r = api_call(
                'get',
                session,
                url=url,
                log=False,
                raise_for_status=False,
                headers={'Accept': 'application/vnd.sgo.update-collection'})
        except requests.exceptions.ConnectionError as e:
            # This can happen during network restart of the instance
            logger.warning(
                'Ignore error during getting status of %s: %s' % (action, e))
            errors += 1
            continue
        if use_410 is True and r.status_code == 410:
            break
        else:
            try:
                r.raise_for_status()
            except requests.exceptions.HTTPError as e:
                logger.warning(
                    'Ignore error during getting status of %s: %s' %
                    (action, e))
                errors += 1
                continue
            results_json = r.json()
            if results_json['status'] != 'IN_PROGRESS':
                logger.info('Final status in response is %s',
                            results_json['status'])
                break
    else:
        raise RuntimeError(
            '%s via API was not finished after %s minutes' %
            (action.capitalize(), timeout / 60))

    if use_410 is True and r.status_code == 410:
        # If status code is not 410, we would have failed already
        logger.info('The %s finished by sending HTTP status %s %s',
                    action, r.status_code, r.reason)
    elif use_410 is False and results_json['status'] == 'SUCCEEDED':
        logger.info('The %s finished with status %s',
                    action, results_json['status'])
    elif results_json['status'] == 'FAILED':
        base_url_p = re.compile(r'^(https?://[^/]+)/.*$')
        base_url_m = base_url_p.match(url)
        base_url = base_url_m.groups()[0]
        results_url = '%s%soutput/' % (base_url, results_json['uri'])
        r = api_call(
            'get',
            session,
            url=results_url,
            headers={'Accept': 'application/vnd.sgo.update.output'})

        log_messages = []
        for object in r.json()['objects']:
            log_message = '*' * 79 + '\n'
            log_message += object['host'] + '\n'
            log_message += '*' * 79 + '\n'
            log_message += object['value']
            log_messages.append(log_message)
        # Cannot raise with output, probably due to the color coding
        logger.error('The %s failed with following log:\n%s',
                     action, '\n\n'.join(log_messages))
        raise RuntimeError('The %s failed' % action)
    else:
        raise RuntimeError('The %s finished with status %s' %
                           (action, results_json['status']))


def get_component_config(config_fixtures, component, extra_config_fn):
    component_config = None

    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               'config', 'awingu',
                                               config_fixtures,
                                               '%s.json' % component))

    if os.path.exists(config_path):
        with open(config_path, 'r') as fp:
            logger.debug('Configuration file found for %s', component)
            try:
                component_config = json.load(fp)
            except:
                logger.info('Something went wrong while parsing %s',
                            config_path)
                logger.info('Please check the JSON file for errors')
                raise
    else:
        logger.debug('No configuration found for %s', component)

    if extra_config_fn:
        extra_config_file = os.path.join(os.path.dirname(__file__),
                                         'config', extra_config_fn)

        with open(extra_config_file, 'r') as fp:
            extra_config = json.load(fp)

        updates = extra_config.get('awingu', {}).get(component, {})

        if updates:
            if isinstance(component_config, dict):
                update_dict(component_config, updates)
            else:
                component_config = updates

    logger.debug('%s configuration: %s', component, str(component_config))
    return component_config


def get_smc_uris(sess, base_url, nested=False):
    headers = {'Accept': 'application/vnd.sgo'}
    smc_uris = api_call('get', sess, base_url + '/smc-api/',
                        headers=headers).json()

    if nested:
        smc_uris.update(_get_nested_smc_uris(sess, base_url, smc_uris))

    return smc_uris
