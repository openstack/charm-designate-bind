# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import amulet
import json
import subprocess
import time


import designateclient.client as designate_client
import designateclient.v1.domains as domains
import designateclient.v1.records as records

import charmhelpers.contrib.openstack.amulet.deployment as amulet_deployment
import charmhelpers.contrib.openstack.amulet.utils as os_amulet_utils

# Use DEBUG to turn on debug logging
u = os_amulet_utils.OpenStackAmuletUtils(os_amulet_utils.DEBUG)


class DesignateBindDeployment(amulet_deployment.OpenStackAmuletDeployment):
    """Amulet tests on a basic designate deployment."""

    TEST_DOMAIN = 'amuletexample.com.'
    TEST_WWW_RECORD = "www.{}".format(TEST_DOMAIN)
    TEST_RECORD = {TEST_WWW_RECORD: '10.0.0.23'}

    def __init__(self, series, openstack=None, source=None, stable=False):
        """Deploy the entire test environment."""
        super(DesignateBindDeployment, self).__init__(series, openstack,
                                                       source, stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        exclude_services = ['mysql', 'mongodb']
        self._auto_wait_for_status(exclude_services=exclude_services)

        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where designate is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'designate-bind'}
        other_services = [{'name': 'mysql'},
                          {'name': 'rabbitmq-server'},
                          {'name': 'keystone'},
                          {'name': 'designate',
                           'location': 'cs:~gnuoy/trusty/designate-0'}]
        super(DesignateBindDeployment, self)._add_services(this_service,
                                                            other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'designate:shared-db': 'mysql:shared-db',
            'designate:amqp': 'rabbitmq-server:amqp',
            'designate:identity-service': 'keystone:identity-service',
            'keystone:shared-db': 'mysql:shared-db',
            'designate:dns-backend': 'designate-bind:dns-backend',
        }
        super(DesignateBindDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        if self.series == 'trusty':
            keystone_config = {'admin-password': 'openstack',
                               'admin-token': 'ubuntutesting',
                               'openstack-origin': 'cloud:trusty-mitaka'}
            designate_config = {'openstack-origin': 'cloud:trusty-mitaka'}
            configs = {
                'keystone': keystone_config,
                'designate': designate_config}
        else:
            keystone_config = {'admin-password': 'openstack',
                               'admin-token': 'ubuntutesting'}
            configs = {'keystone': keystone_config}
        super(DesignateBindDeployment, self)._configure_services(configs)

    def _get_token(self):
        return self.keystone.service_catalog.catalog['token']['id']

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.designate_sentry = self.d.sentry['designate'][0]
        self.designate_bind_sentry = self.d.sentry['designate-bind'][0]
        self.mysql_sentry = self.d.sentry['mysql'][0]
        self.keystone_sentry = self.d.sentry['keystone'][0]
        self.rabbitmq_sentry = self.d.sentry['rabbitmq-server'][0]
        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))
        self.dns_slave_ip = self.designate_bind_sentry.relation(
            'dns-backend',
            'designate:dns-backend')['private-address']
        self.designate_svcs = [
            'designate-agent', 'designate-api', 'designate-central',
            'designate-mdns', 'designate-pool-manager', 'designate-sink',
            'designate-zone-manager',
        ]

        # Authenticate admin with keystone endpoint
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with designate endpoint
        designate_ep = self.keystone.service_catalog.url_for(
            service_type='dns',
            endpoint_type='publicURL')
        keystone_ep = self.keystone.service_catalog.url_for(
            service_type='identity',
            endpoint_type='publicURL')
        self.designate = designate_client.Client(
            version='1',
            auth_url=keystone_ep,
            username="admin",
            password="openstack",
            tenant_name="admin",
            endpoint=designate_ep)

    def check_and_wait(self, check_command, interval=2, max_wait=200,
                       desc=None):
        waited = 0
        while not check_command() or waited > max_wait:
            if desc:
                u.log.debug(desc)
            time.sleep(interval)
            waited = waited + interval
        if waited > max_wait:
            raise Exception('cmd failed {}'.format(check_command))

    def _run_action(self, unit_id, action, *args):
        command = ["juju", "action", "do", "--format=json", unit_id, action]
        command.extend(args)
        print("Running command: %s\n" % " ".join(command))
        output = subprocess.check_output(command)
        output_json = output.decode(encoding="UTF-8")
        data = json.loads(output_json)
        action_id = data[u'Action queued with id']
        return action_id

    def _wait_on_action(self, action_id):
        command = ["juju", "action", "fetch", "--format=json", action_id]
        while True:
            try:
                output = subprocess.check_output(command)
            except Exception as e:
                print(e)
                return False
            output_json = output.decode(encoding="UTF-8")
            data = json.loads(output_json)
            if data[u"status"] == "completed":
                return True
            elif data[u"status"] == "failed":
                return False
            time.sleep(2)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        u.log.debug('Checking system services on units...')

        service_names = {
            self.designate_sentry: self.designate_svcs,
        }

        ret = u.validate_services_by_name(service_names)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

        u.log.debug('OK')

    def test_205_designate_designate_bind_relation(self):
        """Verify the designate to designate-bind dns-backend relation data"""
        u.log.debug('Checking designate:designate-bind dns-backend relation'
                    'data...')
        unit = self.designate_sentry
        relation = ['dns-backend', 'designate-bind:dns-backend']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('designate dns-backend', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_designate_bind_designate_relation(self):
        """Verify the designate_bind to designate dns-backend relation data"""
        u.log.debug('Checking designate-bind:designate dns-backend relation'
                    'data...')
        unit = self.designate_bind_sentry
        relation = ['dns-backend', 'designate:dns-backend']
        expected = {
            'private-address': u.valid_ip,
            'rndckey': u.not_null,
            'algorithm': 'hmac-md5',
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('designate dns-backend', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def get_domain_id(self, domain_name):
        domain_id = None
        for dom in self.designate.domains.list():
            if dom.name == domain_name:
                domain_id = dom.id
        return domain_id

    def get_test_domain_id(self):
        return self.get_domain_id(self.TEST_DOMAIN)

    def check_test_domain_gone(self):
        return not self.get_test_domain_id()

    def check_slave_resolve_test_record(self):
        lookup_cmd = [
            'dig', '+short', '@{}'.format(self.dns_slave_ip),
            self.TEST_WWW_RECORD]
        cmd_out = subprocess.check_output(lookup_cmd).rstrip('\r\n')
        return self.TEST_RECORD[self.TEST_WWW_RECORD] == cmd_out

    def test_400_domain_creation(self):
        """Simple api calls to create domain"""
        u.log.debug('Checking if domain exists before trying to create it')
        old_dom_id = self.get_test_domain_id()
        if old_dom_id:
            u.log.debug('Deleting old domain')
            self.designate.domains.delete(old_dom_id)
        self.check_and_wait(
            self.check_test_domain_gone,
            desc='Waiting for domain to disappear')
        u.log.debug('Creating new domain')
        domain = domains.Domain(
            name=self.TEST_DOMAIN,
            email="fred@amuletexample.com")
        new_domain = self.designate.domains.create(domain)
        assert(new_domain is not None)

        u.log.debug('Creating new test record')
        _record = records.Record(
            name=self.TEST_WWW_RECORD,
            type="A",
            data=self.TEST_RECORD[self.TEST_WWW_RECORD])

        self.designate.records.create(new_domain.id, _record)
        self.check_and_wait(
            self.check_slave_resolve_test_record,
            desc='Waiting for dns record to propagate')
        u.log.debug('Tidy up delete test record')
        self.designate.domains.delete(new_domain.id)
        u.log.debug('OK')
