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


import glob
import os
import time
import subprocess
import hmac
import hashlib
import base64
import json

from ipaddress import IPv4Address, ip_address

import charms_openstack.charm as openstack_charm
import charms_openstack.adapters as adapters
import charms.reactive as reactive
import charmhelpers.core.decorators as ch_decorators
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as host

from charmhelpers.core.hookenv import WORKLOAD_STATES
from charmhelpers.contrib.network import ip as ch_ip
from relations.hacluster.interface_hacluster.common import CRM


LEADERDB_SECRET_KEY = 'rndc_key'
LEADERDB_SYNC_SRC_KEY = 'sync_src'
LEADERDB_SYNC_TIME_KEY = 'sync_time'
CLUSTER_SYNC_KEY = 'sync_request'
WWW_DIR = '/var/www/html'
ZONE_DIR = '/var/cache/bind'
SERVICE_IP_PREFIX = "service_ip_"
COLOCATION_NAME = "service_ip_colocation"
AWAITING_HACLUSTER_FLAG = "service_ip.waiting_for_hacluster"


def install():
    """Use the singleton from the DesignateBindCharm to install the packages
    on the unit

    :returns: None
    """
    DesignateBindCharm.singleton.install()


def set_apparmor():
    """Use the singleton from the DesignateBindCharm to setup apparmor

    :returns: None
    """
    DesignateBindCharm.singleton.set_apparmor()


def init_rndckey():
    """Use the singleton from the DesignateBindCharm to initalise the rndc key
    if possible and not already done

    :returns: str or None. Secret if available, None if not.
    """
    return DesignateBindCharm.singleton.init_rndckey()


def get_rndc_secret():
    """Use the singleton from the DesignateBindCharm to retrieve the RNDC
    secret

    :returns: str or None. Secret if available, None if not.
    """
    return DesignateBindCharm.singleton.get_rndc_secret()


def get_rndc_algorithm():
    """Use the singleton from the DesignateBindCharm to retrieve the RNDC
    algorithm

    :returns: str or None. Algorithm if available, None if not.
    """
    return DesignateBindCharm.singleton.get_rndc_algorithm()


def get_sync_time():
    """Use the singleton from the DesignateBindCharm to retrieve the time of
    the published zone zync target

    :returns: str or None. Current sync target creation time if available, None
                           if not.
    """
    return DesignateBindCharm.singleton.get_sync_time()


def setup_sync():
    """Use the singleton from the DesignateBindCharm to create a zone sync
    target

    :returns: None
    """
    DesignateBindCharm.singleton.setup_sync()


def retrieve_zones(cluster_relation=None):
    """Use the singleton from the DesignateBindCharm to retrieve the zone
    information and install it

    :param hacluster: OpenstackHAPeers() interface class
    :returns: None
    """
    DesignateBindCharm.singleton.retrieve_zones(cluster_relation)


def request_sync(hacluster):
    """Use the singleton from the DesignateBindCharm to request the leader
    creates a sync target

    :param hacluster: OpenstackHAPeers() interface class
    :returns: None
    """
    DesignateBindCharm.singleton.request_sync(hacluster)


def process_requests(hacluster):
    """Use the singleton from the DesignateBindCharm setup a sync target if
    requested

    :param hacluster: OpenstackHAPeers() interface class
    :returns: None
    """
    DesignateBindCharm.singleton.process_requests(hacluster)


def render_all_configs(interfaces_list):
    """Use the singleton from the DesignateBindCharm to render configurations
    and restart services as needed

    :param interfaces_list: List of instances of interface classes.
    :returns: None
    """
    DesignateBindCharm.singleton.render_with_interfaces(interfaces_list)


def assess_status():
    """Just call the DesignateBindCharm.singleton.assess_status() command
    to update status on the unit.

    @returns: None
    """
    DesignateBindCharm.singleton.assess_status()


def parse_service_ip_config():
    """Parse "service_ips" config option value into IP address objects.

    Expected format is comma separated IPv4 or IPv6 addresses.

    :raises: ValueError if "service_ips" is not in expected format.
    :return: List of IPv4 or IPv6 addresses
    :rtype: list[IPv4Address | ipaddress.IPv6Address]
    """
    raw_service_ips = hookenv.config('service_ips')
    service_ips = []
    for ip_addr in raw_service_ips.split(","):
        if ip_addr:
            service_ips.append(ip_address(ip_addr.strip()))
    return service_ips


def remove_service_ips(exclude=None):
    """Remove all service IPs except those stated in the `exclude` parameter.

    :param exclude: List of IPs that should be kept alive.
    :type exclude: list[IPv4Address | ipaddress.IPv6Address]
    :return: None
    """
    if exclude is None:
        exclude = []
    hookenv.log('Clearing Service IPs.', hookenv.INFO)
    ha_cluster = reactive.endpoint_from_flag('ha.connected')

    if not ha_cluster:
        hookenv.log('No relation with "ha-cluster" charm. Nothing to clear.',
                    hookenv.WARNING)
        return

    managed_resources = json.loads(ha_cluster.get_local("json_resources") or
                                   "{}")
    excluded_ips = [str(addr) for addr in exclude]
    for resource in managed_resources:
        if resource.startswith(SERVICE_IP_PREFIX):
            value = resource[len(SERVICE_IP_PREFIX):]
            if value not in excluded_ips:
                ha_cluster.delete_resource(resource)

    ha_cluster.remove_colocation(COLOCATION_NAME)
    ha_cluster.bind_resources()


def add_service_ips(service_ips):
    """Configure (virtual) service IPs on the unit.

    These IPs and their assignment are handled by corosync (hacluster charm)
    and by default they will spread to every unit of designate-bind. Id there
    are more IPs configured than there are units, some units will ned up with
    more than one IP.

    :param service_ips: List of Service IPs to configure
    :type service_ips: list[IPv4Address | ipaddress.IPv6Address]
    :return: None
    """
    ha_cluster = reactive.endpoint_from_flag('ha.connected')

    if not service_ips:
        hookenv.log('Skipping Service IP configuration. No IP addresses '
                    'provided', hookenv.DEBUG)
        reactive.clear_flag(AWAITING_HACLUSTER_FLAG)
        return
    if not ha_cluster:
        hookenv.log('Failed to configure service IPs. "ha-cluster" relation '
                    'missing', hookenv.ERROR)
        reactive.set_flag(AWAITING_HACLUSTER_FLAG)
        return

    crm = CRM()
    all_ip_resources = []

    for ip in service_ips:
        resource_name = "{}{}".format(SERVICE_IP_PREFIX, ip)
        addr_type = "IPaddr2" if isinstance(ip, IPv4Address) else "IPv6addr"
        all_ip_resources.append(resource_name)
        crm.primitive(resource_name, 'ocf:heartbeat:{}'.format(addr_type),
                      params='ip={}'.format(ip), op='monitor interval="10s"')

    crm.colocation(COLOCATION_NAME, -10, *all_ip_resources)
    ha_cluster.manage_resources(crm)


def reconfigure_service_ips():
    """Configure IPs on units according to 'service_ips' config option."""
    hookenv.log("Configuring Service IPs: {}".format(
        hookenv.config('service_ips')), hookenv.INFO)
    try:
        service_ips = parse_service_ip_config()
    except ValueError:
        pass
    else:
        remove_service_ips(exclude=service_ips)
        add_service_ips(service_ips)
    finally:
        assess_status()


@adapters.adapter_property("dns-backend")
def dns_egress_subnets(dns_backend):
    """Generate list of CIDR's for remote units

    Generate a BIND formatted string of semi-colon separated
    CIDR's for all remote units on the dns-backend relation.

    :returns: BIND formatted string of allowed CIDR's for all
              remote units.
    """
    return ';'.join(dns_backend.relation.egress_subnets())


class DNSAdapter(adapters.OpenStackRelationAdapter):

    def __init__(self, relation):
        super(DNSAdapter, self).__init__(relation)

    @property
    def control_listen_ip(self):
        """IP local rndc service listens on

        :returns: str: IP local rndc listens on
        """
        return ch_ip.get_relation_ip('dns-backend')

    @property
    def control_ips(self):
        """Comma delimited list of rndc client IPs

        :returns: str: Comma delimited list of rndc client IPs
        """
        return ';'.join(self.relation.client_ips())

    @property
    def algorithm(self):
        """Algorithm used to encode rndc secret

        :returns: str: Algorithm used to encode rndc secret
        """
        return DesignateBindCharm.get_rndc_algorithm()

    @property
    def secret(self):
        """RNDC Secret

        :returns: str: rndc secret
        """
        return DesignateBindCharm.get_rndc_secret()


class BindAdapters(adapters.OpenStackRelationAdapters):
    """
    Adapters class for the DesignateBind charm.
    """
    relation_adapters = {
        'dns_backend': DNSAdapter,
    }

    def __init__(self, relations):
        super(BindAdapters, self).__init__(
            relations)


class DesignateBindCharm(openstack_charm.OpenStackCharm):

    name = 'designate_bind'
    packages = ['bind9', 'apache2']

    services = ['bind9']

    restart_map = {
        '/etc/bind/named.conf.options': services,
        '/etc/bind/named.conf': services,
        '/etc/bind/rndc.key': services,
    }
    service_type = 'designate_bind'
    default_service = 'bind9'
    adapters_class = BindAdapters
    release = 'icehouse'
    required_relations = []

    group = 'bind'

    def __init__(self, release=None, **kwargs):
        self._ensure_override_service_name()
        super(DesignateBindCharm, self).__init__(release='icehouse', **kwargs)

    @classmethod
    def _ensure_override_service_name(cls):
        """Override the bind9 service to named for focal+

        This class is instantiated for all versions of Ubuntu, but we also need
        to check for the host being focal to override the named service to
        'named'.
        """
        release = host.CompareHostReleases(
            host.lsb_release()['DISTRIB_CODENAME'])
        if release >= 'focal':
            cls.services = ['named']
            cls.restart_map = {
                '/etc/bind/named.conf.options': cls.services,
                '/etc/bind/named.conf': cls.services,
                '/etc/bind/rndc.key': cls.services,
            }
            cls.default_service = 'named'

    @staticmethod
    def get_rndc_algorithm():
        """Algorithm used to encode rndc secret

        :returns: str: Algorithm used to encode rndc secret
        """
        return 'hmac-md5'

    @staticmethod
    def get_rndc_secret():
        """rndc secret

        :returns: str: rndc secret
        """
        return hookenv.leader_get(attribute=LEADERDB_SECRET_KEY)

    @staticmethod
    def get_sync_src():
        """URL published zone file can be retrieved from

        :returns: str: URL published zone file can be retrieved from
        """
        return hookenv.leader_get(attribute=LEADERDB_SYNC_SRC_KEY)

    @staticmethod
    def get_sync_time():
        """Epoch seconds when published sync was created

        :returns: str: Epoch seconds when published sync was created
        """
        return hookenv.leader_get(attribute=LEADERDB_SYNC_TIME_KEY)

    def process_requests(self, hacluster):
        """Check for sync requests and respond

        This should only be called by an application leader.
        Check to see if a peer has requested a sync. If so check if the time
        the request was created is more recent that then published sync target.
        If so, setup a new sync target. When the target is setup the leader db
        is updated with the new sync request time and URL. this will trigger a
        leader-*changed hook on the requesting unit allowing that unit to pick
        up the new file.

        :param hacluster: OpenstackHAPeers() interface class
        :returns: None
        """
        hookenv.log('Processing sync requests', level=hookenv.DEBUG)
        sync_requests = hacluster.retrieve_remote(CLUSTER_SYNC_KEY)
        max_time = 0
        for req in sync_requests:
            if float(req) > max_time:
                max_time = float(req)
        hookenv.log('Newest sync request: {}'.format(max_time),
                    level=hookenv.DEBUG)
        if max_time > float(self.get_sync_time()):
            self.setup_sync()

    def set_sync_info(self, sync_time, sync_file):
        """Update leader DB with sync information

        :param sync_time: str Time sync was created in epoch seconds
        :param sync_file: str Local file containing zone information
        :returns: None
        """
        sync_info = {
            LEADERDB_SYNC_SRC_KEY: 'http://{}:80/zone-syncs/{}'.format(
                hookenv.unit_private_ip(), sync_file),
            LEADERDB_SYNC_TIME_KEY: sync_time,
        }
        hookenv.leader_set(sync_info)

    def generate_rndc_key(self):
        """Generate a RNDC key

        :returns: str Base64 encoded hmac-md5 digest
        """
        key = os.urandom(10)
        dig = hmac.new(key, msg=b'RNDC Secret', digestmod=hashlib.md5).digest()
        return base64.b64encode(dig).decode()

    def init_rndckey(self):
        """Create a RNDC key if needed

        Return the rndc key from the leader DB or if one is not present
        generate a new one.

        :returns: str: rndc key
        """
        secret = DesignateBindCharm.get_rndc_secret()
        hookenv.log('Retrieving secret', level=hookenv.DEBUG)
        if not secret:
            hookenv.log('Secret not found in leader db', level=hookenv.DEBUG)
            if hookenv.is_leader():
                hookenv.log('Creating new secret as leader',
                            level=hookenv.DEBUG)
                secret = self.generate_rndc_key()
                hookenv.leader_set({LEADERDB_SECRET_KEY: secret})
        return secret

    def create_zone_tarball(self, tarfile):
        """Create a tar ball of zone files

        :param tarfile: str Location of tar ball to be created.
        :returns: None
        """
        zone_files = []
        for re in ['juju*', 'slave*', '*nzf', '*nzd']:
            for _file in glob.glob('{}/{}'.format(ZONE_DIR, re)):
                zone_files.append(os.path.basename(_file))
        cmd = ['tar', 'zcvf', tarfile]
        cmd.extend(zone_files)
        subprocess.check_call(cmd, cwd=ZONE_DIR)

    def setup_sync_dir(self, sync_time):
        """Create directory to store zone sync files

        :returns: None
        """
        # NOTE(jamespage): sync_time is not used in the path?
        sync_dir = '{}/zone-syncs'.format(WWW_DIR)
        try:
            os.mkdir(sync_dir, 0o755)
        except FileExistsError:
            os.chmod(sync_dir, 0o755)
        return sync_dir

    def create_sync_src_info_file(self):
        """Touch a file which indicates where this sync file came from

        :returns: None
        """
        unit_name = hookenv.local_unit().replace('/', '_')
        touch_file = '{}/juju-zone-src-{}'.format(ZONE_DIR, unit_name)
        open(touch_file, 'w+').close()

    def setup_sync(self):
        """Setup a sync target

        Stop bind and tar up zone files, and start bind. Then update leaderdb
        with details of new sync.

        :returns: None
        """
        hookenv.log('Setting up zone info for collection', level=hookenv.DEBUG)
        sync_time = str(time.time())
        sync_dir = self.setup_sync_dir(sync_time)
        self.create_sync_src_info_file()
        # FIXME Try freezing DNS rather than stopping bind
        self.service_control('stop', [self.default_service])
        tar_file = '{}/{}.tar.gz'.format(sync_dir, sync_time)
        self.create_zone_tarball(tar_file)
        self.service_control('start', [self.default_service])
        self.set_sync_info(sync_time, '{}.tar.gz'.format(sync_time))

    def service_control(self, cmd, services):
        """Control listed services

        :param cmd: str Action to take on service (stop, start, restart)
        :returns: None
        """

        cmds = {
            'stop': host.service_stop,
            'start': host.service_start,
            'restart': host.service_restart,
        }
        for service in services:
            cmds[cmd](service)

    def request_sync(self, hacluster):
        """Request peer sets up a sync target

        Send a request via the cluster relation asking for a sync target to be
        setup.

        :param hacluster: OpenstackHAPeers() interface class
        :returns: None
        """
        request_time = str(time.time())
        hacluster.send_all({CLUSTER_SYNC_KEY: request_time}, store_local=True)
        reactive.set_state('sync.request.sent')

    @ch_decorators.retry_on_exception(3, base_delay=2,
                                      exc_type=subprocess.CalledProcessError)
    def wget_file(self, url, target_dir):
        """Retireve file from url into target_dir

        :param url: str Retrieve file from this url
        :param target_dir: Place file in this directory
        :returns: None
        """
        print("{} {}".format(url, target_dir))
        # set arg no-proxy as this should be a direct connection on
        # dns-backend space lp#1796969
        cmd = ['wget', url, '--no-proxy', '--retry-connrefused', '-t', '10']
        subprocess.check_call(cmd, cwd=target_dir)

    def retrieve_zones(self, cluster_relation=None):
        """Retrieve and install zones file

        Check if published sync target was created after this units sync
        request was sent, if it was install the zones file. Alternatively if
        no peer relation was set then assume the current sync target is to be
        used regardless of when it was created.

        :param cluster_relation: OpenstackHAPeers() interface class
        :returns: None
        """

        request_time = None
        if cluster_relation:
            request_times = list(set(
                cluster_relation.retrieve_local(CLUSTER_SYNC_KEY)))
            request_time = request_times[0]
        sync_time = DesignateBindCharm.get_sync_time()
        if request_time and sync_time and request_time > sync_time:
            hookenv.log(('Request for sync sent but remote sync time is too'
                         ' old, defering until a more up-to-date target is '
                         'available'),
                        level=hookenv.WARNING)
        else:
            url = DesignateBindCharm.get_sync_src()
            if url:
                self.service_control('stop', [self.default_service])
                self.wget_file(url, ZONE_DIR)
                tar_file = url.split('/')[-1]
                subprocess.check_call(['tar', 'xf', tar_file], cwd=ZONE_DIR)
                os.remove('{}/{}'.format(ZONE_DIR, tar_file))
                self.service_control('start', [self.default_service])
                reactive.remove_state('sync.request.sent')
                reactive.set_state('zones.initialised')
            else:
                hookenv.log(('Leader has not set valid url for zone download '
                             ' defering until leader provides url'),
                            level=hookenv.WARNING)

    def set_apparmor(self):
        """Disbale apparmor for named

        This is currently specified in the designate documentation
        http://docs.openstack.org/developer/designate/getting-started.html

        TODO: Check this is *really* needed

        :returns: None
        """
        apparmor_file = '/etc/apparmor.d/disable/usr.sbin.named'
        if not os.path.isfile(apparmor_file):
            open(apparmor_file, 'w').close()
            host.service_reload('apparmor')

    def _assess_status(self):
        """Overall unit status assessment.

        This override appends additional status checks related to the
        service_ip configuration.
        """
        super()._assess_status()
        # Subordinate charm "ha-cluster" is needed for management of Service
        # IPs. If service IPs are configured but there's no relation with
        # "hacluster", put unit into blocked state.
        try:
            parse_service_ip_config()
        except ValueError:
            bad_format_msg = ('Config option "service_ips" does not have '
                              'an expected format.')
            hookenv.status_set(WORKLOAD_STATES.BLOCKED, bad_format_msg)
            return

        if reactive.is_flag_set(AWAITING_HACLUSTER_FLAG):
            hookenv.log('Config option "service_ips" is set but relation with '
                        '"hacluster" is missing. Either add subordinate '
                        '"hacluster" charm or unconfigure "service_ips" '
                        'option',
                        hookenv.ERROR)
            hookenv.status_set(WORKLOAD_STATES.BLOCKED, 'Failed to configure '
                                                        '"service_ips", '
                                                        'hacluster relation is'
                                                        ' missing.')
