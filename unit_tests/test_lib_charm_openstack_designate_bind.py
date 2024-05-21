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


from unittest import mock
import sys

from ipaddress import IPv4Address, IPv6Address

# Modules imported from other interfaces/layers need to be mocked
sys.modules[
    'relations.hacluster.interface_hacluster.common'
] = mock.MagicMock()

import charms_openstack.test_utils as test_utils

import charm.openstack.designate_bind as designate_bind


def FakeConfig(init_dict):

    def _config(key=None):
        return init_dict[key] if key else init_dict

    return _config


class Helper(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch('charmhelpers.core.hookenv.config', name='ch_config')
        self.ch_config.side_effect = lambda: {'ssl_param': None}
        self.patch_object(designate_bind, "host", name="ch_core_host")
        self.ch_core_host.lsb_release.return_value = {
            "DISTRIB_CODENAME": "bionic"
        }
        # simply the CompareHostReleases to just return then string for
        # comparisons. (won't work for xenial/bionic)
        self.ch_core_host.CompareHostReleases.side_effect = lambda x: x
        charm = designate_bind.DesignateBindCharm(release='icehouse')
        self.patch("charms_openstack.charm.core.default_get_charm_instance",
                   new=lambda *_, **__: charm)
        self.patch('charms_openstack.charm.core._singleton', new=None)


class TestOpenStackDesignateBind(Helper):

    def test_install(self):
        charm = designate_bind.DesignateBindCharm.singleton
        self.patch_object(charm, 'install')
        designate_bind.install()
        self.install.assert_called_once_with()

    def test_service_is_bind9_pre_focal(self):
        charm = designate_bind.DesignateBindCharm.singleton
        self.assertEqual(charm.services, ["bind9"])
        for v in charm.restart_map.values():
            self.assertEqual(v, ["bind9"])
        self.assertEqual(charm.default_service, "bind9")

    def test_service_is_bind9_when_bionic(self):
        self.ch_core_host.lsb_release.return_value = {
            "DISTRIB_CODENAME": "bionic"
        }
        charm = designate_bind.DesignateBindCharm.singleton
        self.assertEqual(charm.services, ["bind9"])
        for v in charm.restart_map.values():
            self.assertEqual(v, ["bind9"])
        self.assertEqual(charm.default_service, "bind9")

    def test_service_is_named_focal_plus(self):
        self.ch_core_host.lsb_release.return_value = {
            "DISTRIB_CODENAME": "focal"
        }
        actual_charm = designate_bind.DesignateBindCharm(release='icehouse')
        self.patch("charms_openstack.charm.core.default_get_charm_instance",
                   new=lambda *_, **__: actual_charm)
        charm = designate_bind.DesignateBindCharm.singleton
        self.assertEqual(charm.services, ["named"])
        for v in charm.restart_map.values():
            self.assertEqual(v, ["named"])
        self.assertEqual(charm.default_service, "named")

    def test_init_rndckey(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton, 'init_rndckey')
        designate_bind.init_rndckey()
        self.init_rndckey.assert_called_once_with()

    def test_get_rndc_secret(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'get_rndc_secret')
        designate_bind.get_rndc_secret()
        self.get_rndc_secret.assert_called_once_with()

    def test_get_rndc_algorithm(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'get_rndc_algorithm')
        designate_bind.get_rndc_algorithm()
        self.get_rndc_algorithm.assert_called_once_with()

    def test_get_sync_time(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'get_sync_time')
        designate_bind.get_sync_time()
        self.get_sync_time.assert_called_once_with()

    def test_setup_sync(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton, 'setup_sync')
        designate_bind.setup_sync()
        self.setup_sync.assert_called_once_with()

    def test_retrieve_zones(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'retrieve_zones')
        designate_bind.retrieve_zones('hacluster')
        self.retrieve_zones.assert_called_once_with('hacluster')

    def test_request_sync(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'request_sync')
        designate_bind.request_sync('hacluster')
        self.request_sync.assert_called_once_with('hacluster')

    def test_process_requests(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'process_requests')
        designate_bind.process_requests('hacluster')
        self.process_requests.assert_called_once_with('hacluster')

    def test_render_all_configs(self):
        self.patch_object(
            designate_bind.DesignateBindCharm.singleton,
            'render_with_interfaces')
        designate_bind.render_all_configs('interface_list')
        self.render_with_interfaces.assert_called_once_with('interface_list')


class TestServiceIPFunctions(Helper):
    """Collection of tests for functions doing 'service_ip' configuration."""

    def test_parse_service_ip_config(self):
        """Test function parsing 'service_ips' config option."""
        service_ips = "10.0.0.1, 10.0.0.2, 2001:db8::2:1"

        with mock.patch.object(designate_bind.hookenv, 'config') as config:
            config.return_value = service_ips
            parsed_ips = designate_bind.parse_service_ip_config()

        expected_output = [
            IPv4Address("10.0.0.1"),
            IPv4Address("10.0.0.2"),
            IPv6Address("2001:db8::2:1")
        ]

        self.assertEqual(expected_output, parsed_ips)

    def test_remove_service_ips(self):
        """Test removing already configured Service IPs."""
        ip_to_remove = IPv4Address("10.0.0.1")
        ip_to_retain = IPv4Address("10.0.0.2")
        configured_resources = '["{0}{1}", "{0}{2}"]'.format(
            designate_bind.SERVICE_IP_PREFIX,
            ip_to_remove,
            ip_to_retain
        )
        ha_cluster = mock.MagicMock()
        ha_cluster.get_local.return_value = configured_resources

        with mock.patch.object(designate_bind.reactive, 'endpoint_from_flag',
                               return_value=ha_cluster):
            designate_bind.remove_service_ips(exclude=[ip_to_retain])

        ha_cluster.delete_resource.assert_called_once_with("{}{}".format(
            designate_bind.SERVICE_IP_PREFIX, ip_to_remove
        ))
        ha_cluster.remove_colocation.assert_called_once_with(
            designate_bind.COLOCATION_NAME
        )
        ha_cluster.bind_resources.assert_called_once_with()

    def test_remove_service_ips_no_hacluster(self):
        """Test that warning is logged if there's no hacluster."""
        with mock.patch.object(designate_bind.reactive, 'endpoint_from_flag',
                               return_value=None):
            designate_bind.remove_service_ips()

        expected_message = ('No relation with "ha-cluster" charm. Nothing to '
                            'clear.')
        expected_level = designate_bind.hookenv.WARNING
        designate_bind.hookenv.log.assert_called_with(expected_message,
                                                      expected_level)

    def test_add_service_ips(self):
        """Test configuring Service IP via hacluster resources."""
        ha_cluster_mock = mock.MagicMock()
        crm_mock = mock.MagicMock()
        crm_patch = mock.patch.object(designate_bind, 'CRM',
                                      return_value=crm_mock)
        crm_patch.start()

        add_ips = [IPv4Address("10.0.0.1"), IPv6Address("2001:db8::2:1")]
        expected_primitive_calls = []
        all_ip_resources = []
        for ip_ in add_ips:
            resource = "{}{}".format(designate_bind.SERVICE_IP_PREFIX, ip_)
            ip_type = "IPaddr2" if isinstance(ip_, IPv4Address) else "IPv6addr"
            expected_primitive_calls.append(mock.call(
                resource,
                "ocf:heartbeat:{}".format(ip_type),
                params="ip={}".format(ip_),
                op='monitor interval="10s"'
            ))
            all_ip_resources.append(resource)

        with mock.patch.object(designate_bind.reactive, 'endpoint_from_flag',
                               return_value=ha_cluster_mock):
            designate_bind.add_service_ips(add_ips)

        crm_mock.primitive.assert_has_calls(expected_primitive_calls)
        crm_mock.colocation.assert_called_once_with(
            designate_bind.COLOCATION_NAME,
            -10,
            *all_ip_resources
        )
        ha_cluster_mock.manage_resources.assert_called_once_with(crm_mock)

        crm_patch.stop()

    def test_add_service_ips_no_config(self):
        """Test that function passes when there are no IPs to configure."""
        ha_cluster_mock = mock.MagicMock()

        with mock.patch.object(designate_bind.reactive, 'endpoint_from_flag',
                               return_value=ha_cluster_mock):
            designate_bind.add_service_ips([])

        ha_cluster_mock.manage_resources.assert_not_called()
        # Assert that we also clear flag that signals that service_ips config
        # option is configured and charm is waiting for hacluster relation.
        designate_bind.reactive.clear_flag.assert_called_with(
            designate_bind.AWAITING_HACLUSTER_FLAG
        )

    def test_add_service_ips_no_hacluster(self):
        """Test that function sets correct flag if it's missing hacluster."""
    with mock.patch.object(designate_bind.reactive, 'endpoint_from_flag',
                           return_value=None):
        designate_bind.add_service_ips([IPv4Address("10.0.0.1")])

    designate_bind.reactive.set_flag.assert_called_with(
        designate_bind.AWAITING_HACLUSTER_FLAG
    )


class TestEgressSubnets(Helper):

    def test_egress_subnets(self):
        dns_backend = mock.MagicMock()
        dns_backend.relation.egress_subnets.return_value = [
            "10.5.2.1/32",
            "10.6.20.1/32",
            "10.7.20.21/32",
        ]
        self.assertEqual(
            designate_bind.dns_egress_subnets(dns_backend),
            "10.5.2.1/32;10.6.20.1/32;10.7.20.21/32",
        )


class TestDNSAdapter(Helper):

    def test_control_listen_ip(self):
        relation = mock.MagicMock()
        self.patch_object(designate_bind.ch_ip, 'get_relation_ip')
        self.patch_object(designate_bind.hookenv, 'unit_private_ip')
        self.get_relation_ip.return_value = 'ip1'
        a = designate_bind.DNSAdapter(relation)
        self.assertEqual(a.control_listen_ip, 'ip1')

    def test_control_ips(self):
        relation = mock.MagicMock()
        relation.client_ips.return_value = ['ip1', 'ip2']
        a = designate_bind.DNSAdapter(relation)
        self.assertEqual(a.control_ips, 'ip1;ip2')

    def test_algorithm(self):
        relation = mock.MagicMock()
        self.patch_object(
            designate_bind.DesignateBindCharm, 'get_rndc_algorithm')
        self.get_rndc_algorithm.return_value = 'algo1'
        a = designate_bind.DNSAdapter(relation)
        self.assertEqual(a.algorithm, 'algo1')

    def test_secret(self):
        relation = mock.MagicMock()
        self.patch_object(designate_bind.DesignateBindCharm, 'get_rndc_secret')
        self.get_rndc_secret.return_value = 'secret1'
        a = designate_bind.DNSAdapter(relation)
        self.assertEqual(a.secret, 'secret1')


class TestBindAdapters(Helper):

    def test_bind_adapters(self):
        dns_backend_relation = mock.MagicMock()
        dns_backend_relation.endpoint_name = 'dns_backend'
        b = designate_bind.BindAdapters([dns_backend_relation])
        # ensure that the relevant things got put on.
        self.assertTrue(
            isinstance(
                b.dns_backend,
                designate_bind.adapters.OpenStackRelationAdapter))


class TestDesignateBindCharm(Helper):

    def test_get_rndc_algorithm(self):
        self.assertEqual(
            designate_bind.DesignateBindCharm.get_rndc_algorithm(),
            'hmac-md5'
        )

    def test_get_rndc_secret(self):
        self.patch_object(designate_bind.hookenv, 'leader_get')
        self.leader_get.return_value = 'secret1'
        self.assertEqual(
            designate_bind.DesignateBindCharm.get_rndc_secret(),
            'secret1'
        )

    def test_get_sync_src(self):
        self.patch_object(designate_bind.hookenv, 'leader_get')
        self.leader_get.return_value = 'http://ip1/my.tar'
        self.assertEqual(
            designate_bind.DesignateBindCharm.get_sync_src(),
            'http://ip1/my.tar'
        )

    def test_get_sync_time(self):
        self.patch_object(designate_bind.hookenv, 'leader_get')
        self.leader_get.return_value = '100'
        self.assertEqual(
            designate_bind.DesignateBindCharm.get_sync_time(),
            '100'
        )

    def test_process_requests(self):
        hacluster = mock.MagicMock()
        self.patch_object(designate_bind.hookenv, 'log')
        self.patch_object(designate_bind.DesignateBindCharm, 'setup_sync')
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_time')
        a = designate_bind.DesignateBindCharm()
        # No queued requests
        hacluster.retrieve_remote.return_value = []
        self.get_sync_time.return_value = 20
        a.process_requests(hacluster)
        self.assertFalse(self.setup_sync.called)
        # No request since last sync
        self.setup_sync.reset_mock()
        hacluster.retrieve_remote.return_value = ['10']
        self.get_sync_time.return_value = 20
        a.process_requests(hacluster)
        self.assertFalse(self.setup_sync.called)
        # New request present
        self.setup_sync.reset_mock()
        hacluster.retrieve_remote.return_value = ['10', '30']
        self.get_sync_time.return_value = 20
        a.process_requests(hacluster)
        self.assertTrue(self.setup_sync.called)

    def test_set_sync_info(self):
        self.patch_object(designate_bind.hookenv, 'leader_set')
        self.patch_object(designate_bind.hookenv, 'unit_private_ip')
        self.unit_private_ip.return_value = 'ip1'
        a = designate_bind.DesignateBindCharm()
        a.set_sync_info('20', '/tmp/tarball.tar')
        self.leader_set.assert_called_once_with({
            'sync_time': '20',
            'sync_src': 'http://ip1:80/zone-syncs//tmp/tarball.tar'})

    def test_generate_rndc_key(self):
        hmac_mock = mock.MagicMock()
        self.patch_object(designate_bind.os, 'urandom', return_value='seed')
        self.patch_object(designate_bind.hmac, 'new', return_value=hmac_mock)
        self.patch_object(
            designate_bind.base64, 'b64encode', return_value=hmac_mock)
        self.patch_object(designate_bind.hashlib, 'md5', new='md5lib')
        a = designate_bind.DesignateBindCharm()
        a.generate_rndc_key()
        self.new.assert_called_once_with(
            'seed',
            digestmod='md5lib',
            msg=b'RNDC Secret')

    def test_init_rndckey(self):
        self.patch_object(designate_bind.hookenv, 'log')
        self.patch_object(designate_bind.DesignateBindCharm, 'get_rndc_secret')
        self.patch_object(
            designate_bind.DesignateBindCharm, 'generate_rndc_key')
        self.patch_object(designate_bind.hookenv, 'leader_set')
        self.patch_object(designate_bind.hookenv, 'is_leader')
        a = designate_bind.DesignateBindCharm()
        # Test secret already stored
        self.get_rndc_secret.return_value = 'mysecret'
        self.assertEqual(a.init_rndckey(), 'mysecret')
        # Test need new secret (Leader)
        self.get_rndc_secret.return_value = None
        self.generate_rndc_key.return_value = 'newsecret'
        self.is_leader.return_value = True
        self.assertEqual(a.init_rndckey(), 'newsecret')
        self.leader_set.assert_called_once_with({'rndc_key': 'newsecret'})
        # Test need new secret (Not Leader)
        self.get_rndc_secret.return_value = None
        self.is_leader.return_value = False
        self.assertEqual(a.init_rndckey(), None)

    def test_create_zone_tarball(self):
        self.patch_object(designate_bind.glob, 'glob')
        self.patch_object(designate_bind.subprocess, 'check_call')
        _files = {
            '/var/cache/bind/juju*': ['jujufile1'],
            '/var/cache/bind/slave*': ['slavefile1'],
            '/var/cache/bind/*nzf': ['nsffile'],
            '/var/cache/bind/*nzd': ['nsdfile']}
        self.glob.side_effect = lambda x: _files[x]
        a = designate_bind.DesignateBindCharm()
        a.create_zone_tarball('/tmp/tarball.tar')
        self.check_call.assert_called_once_with([
            'tar', 'zcvf', '/tmp/tarball.tar', 'jujufile1', 'slavefile1',
            'nsffile', 'nsdfile'], cwd='/var/cache/bind')

    def test_setup_sync_dir(self):
        self.patch_object(designate_bind.os, 'mkdir')
        self.patch_object(designate_bind.os, 'chmod')
        a = designate_bind.DesignateBindCharm()
        a.setup_sync_dir('100')
        self.mkdir.assert_called_once_with('/var/www/html/zone-syncs', 493)
        self.assertFalse(self.chmod.called)
        # Test dir does not exist
        self.mkdir.side_effect = FileExistsError
        a.setup_sync_dir('100')
        self.chmod.assert_called_once_with('/var/www/html/zone-syncs', 493)

    def test_create_sync_src_info_file(self):
        self.patch_object(
            designate_bind.hookenv, 'local_unit', return_value='unit/1')
        a = designate_bind.DesignateBindCharm()
        with mock.patch('builtins.open') as bob:
            a.create_sync_src_info_file()
        bob.assert_called_once_with(
            '/var/cache/bind/juju-zone-src-unit_1',
            'w+')

    def test_setup_sync(self):
        self.patch_object(designate_bind.hookenv, 'log')
        self.patch_object(designate_bind.DesignateBindCharm, 'setup_sync_dir')
        self.patch_object(designate_bind.time, 'time')
        self.patch_object(
            designate_bind.DesignateBindCharm,
            'create_sync_src_info_file')
        self.patch_object(designate_bind.DesignateBindCharm, 'service_control')
        self.patch_object(
            designate_bind.DesignateBindCharm, 'create_zone_tarball')
        self.patch_object(
            designate_bind.DesignateBindCharm, 'set_sync_info')
        self.setup_sync_dir.return_value = '/tmp/zonefiles'
        self.time.return_value = 100
        a = designate_bind.DesignateBindCharm()
        a.setup_sync()
        self.setup_sync_dir.assert_called_once_with('100')
        self.create_sync_src_info_file.assert_called_once_with()
        ctrl_calls = [
            mock.call('stop', ['bind9']),
            mock.call('start', ['bind9'])]
        self.service_control.assert_has_calls(ctrl_calls)
        self.create_zone_tarball.assert_called_once_with(
            '/tmp/zonefiles/100.tar.gz')
        self.set_sync_info.assert_called_once_with('100', '100.tar.gz')

    def test_service_control(self):
        self.patch_object(designate_bind.host, 'service_stop')
        a = designate_bind.DesignateBindCharm()
        a.service_control('stop', ['svc1', 'svc2'])
        ctrl_calls = [
            mock.call('svc1'),
            mock.call('svc2')]
        self.service_stop.assert_has_calls(ctrl_calls)

    def test_request_sync(self):
        self.patch_object(designate_bind.time, 'time')
        relation = mock.MagicMock()
        self.patch_object(designate_bind.reactive, 'set_state')
        self.time.return_value = 100
        a = designate_bind.DesignateBindCharm()
        a.request_sync(relation)
        relation.send_all.assert_called_once_with(
            {'sync_request': '100'},
            store_local=True)
        self.set_state.assert_called_once_with('sync.request.sent')

    def test_wget_file(self):
        # retry_on_exception patched out in __init__.py
        self.patch_object(designate_bind.subprocess, 'check_call')
        a = designate_bind.DesignateBindCharm()
        a.wget_file('http://ip1/tarfile.tar', '/tmp')
        self.check_call.assert_called_once_with(
            ['wget', 'http://ip1/tarfile.tar', '--no-proxy',
             '--retry-connrefused', '-t', '10'],
            cwd='/tmp'
        )

    def test_retrieve_zones_cluster_relation(self):
        relation = mock.MagicMock()
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_time')
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_src')
        self.patch_object(designate_bind.DesignateBindCharm, 'service_control')
        self.patch_object(designate_bind.hookenv, 'log')
        self.patch_object(designate_bind.reactive, 'set_state')
        self.patch_object(designate_bind.reactive, 'remove_state')
        self.patch_object(designate_bind.os, 'remove')
        self.patch_object(designate_bind.subprocess, 'check_call')
        self.patch_object(designate_bind.DesignateBindCharm, 'wget_file')
        self.get_sync_src.return_value = 'http://ip1/tarfile.tar'
        ctrl_calls = [
            mock.call('stop', ['bind9']),
            mock.call('start', ['bind9'])]
        a = designate_bind.DesignateBindCharm()
        # Using cluster_relation, no sync needed
        relation.retrieve_local.return_value = ['30']
        self.get_sync_time.return_value = '20'
        a.retrieve_zones(relation)
        self.assertFalse(self.service_control.called)
        # Using cluster_relation, sync needed
        self.service_control.reset_mock()
        relation.retrieve_local.return_value = ['10']
        self.get_sync_time.return_value = '20'
        a.retrieve_zones(relation)
        self.service_control.assert_has_calls(ctrl_calls)
        self.check_call.assert_called_once_with(
            ['tar', 'xf', 'tarfile.tar'], cwd='/var/cache/bind')
        self.wget_file.assert_called_once_with(
            'http://ip1/tarfile.tar',
            '/var/cache/bind')

    def test_retrieve_zones_cluster_relation_nourl(self):
        relation = mock.MagicMock()
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_time')
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_src')
        self.patch_object(designate_bind.DesignateBindCharm, 'wget_file')
        self.patch_object(designate_bind.hookenv, 'log')
        self.get_sync_src.return_value = None
        relation.retrieve_local.return_value = ['10']
        self.get_sync_time.return_value = '20'
        a = designate_bind.DesignateBindCharm()
        a.retrieve_zones(relation)
        self.assertFalse(self.wget_file.called)

    def test_retrieve_zones_no_cluster_relation(self):
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_time')
        self.patch_object(designate_bind.DesignateBindCharm, 'get_sync_src')
        self.patch_object(designate_bind.DesignateBindCharm, 'service_control')
        self.patch_object(designate_bind.hookenv, 'log')
        self.patch_object(designate_bind.reactive, 'set_state')
        self.patch_object(designate_bind.reactive, 'remove_state')
        self.patch_object(designate_bind.os, 'remove')
        self.patch_object(designate_bind.subprocess, 'check_call')
        self.patch_object(designate_bind.DesignateBindCharm, 'wget_file')
        self.get_sync_src.return_value = 'http://ip1/tarfile.tar'
        ctrl_calls = [
            mock.call('stop', ['bind9']),
            mock.call('start', ['bind9'])]
        a = designate_bind.DesignateBindCharm()
        self.get_sync_time.return_value = '20'
        a.retrieve_zones()
        self.service_control.assert_has_calls(ctrl_calls)
        self.check_call.assert_called_once_with(
            ['tar', 'xf', 'tarfile.tar'], cwd='/var/cache/bind')
        self.wget_file.assert_called_once_with(
            'http://ip1/tarfile.tar',
            '/var/cache/bind')

    def test_set_apparmor(self):
        self.patch_object(designate_bind.os.path, 'isfile')
        a = designate_bind.DesignateBindCharm()
        self.isfile.return_value = True
        with mock.patch('builtins.open') as bob:
            a.set_apparmor()
        self.assertFalse(bob.called)
        self.isfile.return_value = False
        with mock.patch('builtins.open') as bob:
            a.set_apparmor()
        bob.assert_called_once_with(
            '/etc/apparmor.d/disable/usr.sbin.named',
            'w')

    def test_asses_status_passes(self):
        """Test scenario where _assess_status passes without blocking charm."""
        self.patch_object(designate_bind.openstack_charm.OpenStackCharm,
                          '_assess_status')
        self.patch_object(designate_bind, 'parse_service_ip_config')
        designate_bind.reactive.is_flag_set.return_value = False

        charm_ = designate_bind.DesignateBindCharm()
        charm_._assess_status()

        designate_bind.parse_service_ip_config.assert_called_once_with()
        designate_bind.hookenv.status_set.assert_not_called()

    def test_assess_status_bad_ip_config(self):
        """Test that unit is blocked if 'service_ips' config has bad format."""
        self.patch_object(designate_bind.openstack_charm.OpenStackCharm,
                          '_assess_status')
        self.patch_object(designate_bind, 'parse_service_ip_config')
        designate_bind.parse_service_ip_config.side_effect = ValueError

        charm_ = designate_bind.DesignateBindCharm()
        charm_._assess_status()

        expected_state = designate_bind.hookenv.WORKLOAD_STATES.BLOCKED
        expected_message = ('Config option "service_ips" does not have an '
                            'expected format.')

        designate_bind.hookenv.status_set.assert_called_once_with(
            expected_state, expected_message
        )

    def test_assess_status_blocks_on_awaiting_hacluster(self):
        """Test that unit is blocked if it's awaiting hacluster relation.

        This occurs when 'service_ips' config option is set but relation with
        hacluster charm is missing.
        """
        self.patch_object(designate_bind.openstack_charm.OpenStackCharm,
                          '_assess_status')
        self.patch_object(designate_bind, 'parse_service_ip_config')
        designate_bind.reactive.is_flag_set.return_value = True

        charm_ = designate_bind.DesignateBindCharm()
        charm_._assess_status()

        expected_state = designate_bind.hookenv.WORKLOAD_STATES.BLOCKED
        expected_message = ('Failed to configure "service_ips", hacluster '
                            'relation is missing.')

        designate_bind.hookenv.status_set.assert_called_once_with(
            expected_state, expected_message
        )
