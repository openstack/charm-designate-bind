import glob
import os
import time
import subprocess

import charms_openstack.adapters as adapters
import charms.reactive as reactive
import charmhelpers.core.decorators as ch_decorators
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as host
import charmhelpers.core.templating as templating
import charmhelpers.fetch as fetch

BIND_DIR = '/etc/bind'
NAMED_OPTIONS = 'named.conf.options'
NAMED_CONF = 'named.conf'
RNDC_KEY = 'rndc.key'
BIND_SERVICES = ['bind9']
BIND_PACKAGES = ['bind9', 'apache2']
LEADERDB_SECRET_KEY = 'rndc_key'
LEADERDB_SYNC_SRC_KEY = 'sync_src'
LEADERDB_SYNC_TIME_KEY = 'sync_time'
CLUSTER_SYNC_KEY = 'sync_request'
WWW_DIR = '/var/www/html'
ZONE_DIR = '/var/cache/bind/'


def init_rndckey():
    secret = hookenv.leader_get(attribute=LEADERDB_SECRET_KEY)
    hookenv.log('Retrieving secret', level=hookenv.DEBUG)
    if not secret:
        hookenv.log('Secret not found in leader db', level=hookenv.DEBUG)
        if hookenv.is_leader():
            hookenv.log('Creating new secret as leader',
                        level=hookenv.DEBUG)
            secret = host.pwgen(length=24)
            hookenv.leader_set({LEADERDB_SECRET_KEY: secret})
    return secret


def get_rndc_algorithm():
    return 'hmac-md5'


def get_rndc_secret():
    return hookenv.leader_get(attribute=LEADERDB_SECRET_KEY)


def get_sync_src():
    return hookenv.leader_get(attribute=LEADERDB_SYNC_SRC_KEY)


def get_sync_time():
    return hookenv.leader_get(attribute=LEADERDB_SYNC_TIME_KEY)


def create_zone_tarball(tarfile):
    zone_files = []
    for re in ['juju*', 'slave*', '*nzf']:
        for _file in glob.glob('{}/{}'.format(ZONE_DIR, re)):
            zone_files.append(os.path.basename(_file))
    cmd = ['tar', 'zcvf', tarfile]
    cmd.extend(zone_files)
    subprocess.check_call(cmd, cwd=ZONE_DIR)


def setup_sync():
    hookenv.log('Setting up zone info for collection', level=hookenv.DEBUG)
    sync_time = str(time.time())
    sync_dir = '{}/zone-syncs'.format(WWW_DIR, sync_time)
    try:
        os.mkdir(sync_dir, 0o755)
    except FileExistsError:
        os.chmod(sync_dir, 0o755)
    unit_name = hookenv.local_unit().replace('/', '_')
    touch_file = '{}/juju-zone-src-{}'.format(ZONE_DIR, unit_name)
    open(touch_file, 'w+').close()
    # FIXME Try freezing DNS rather than stopping bind
    for service in BIND_SERVICES:
        host.service_stop(service)
    tar_file = '{}/{}.tar.gz'.format(sync_dir, sync_time)
    create_zone_tarball(tar_file)
    for service in BIND_SERVICES:
        host.service_start(service)
    set_sync_info(sync_time, '{}.tar.gz'.format(sync_time))


def set_sync_info(sync_time, sync_file):
    sync_info = {
        LEADERDB_SYNC_SRC_KEY: 'http://{}:80/zone-syncs/{}'.format(
            hookenv.unit_private_ip(), sync_file),
        LEADERDB_SYNC_TIME_KEY: sync_time,
    }
    hookenv.leader_set(sync_info)


def request_sync(hacluster):
    request_time = str(time.time())
    hacluster.send_all({CLUSTER_SYNC_KEY: request_time}, store_local=True)
    reactive.set_state('sync.request.sent')


@ch_decorators.retry_on_exception(3, base_delay=2,
                                  exc_type=subprocess.CalledProcessError)
def wget_file(url, target_dir):
        cmd = ['wget', url, '--retry-connrefused', '-t', '10']
        subprocess.check_call(cmd, cwd=ZONE_DIR)


def retrieve_zones(cluster_relation=None):
    if cluster_relation:
        request_time = cluster_relation.retrieve_local(CLUSTER_SYNC_KEY)
    sync_time = hookenv.leader_get(LEADERDB_SYNC_TIME_KEY)
    if request_time and request_time > sync_time:
        hookenv.log(('Request for sync sent but remote sync time is too old, '
                     'defering until a more up-to-date target is available'),
                    level=hookenv.WARNING)
    else:
        for service in BIND_SERVICES:
            host.service_stop(service)
        url = hookenv.leader_get(LEADERDB_SYNC_SRC_KEY)
        wget_file(url, ZONE_DIR)
        tar_file = url.split('/')[-1]
        subprocess.check_call(['tar', 'xf', tar_file], cwd=ZONE_DIR)
        os.remove('{}/{}'.format(ZONE_DIR, tar_file))
        for service in BIND_SERVICES:
            host.service_start(service)
        reactive.remove_state('sync.request.sent')
        reactive.set_state('zones.initialised')


class DNSAdapter(adapters.OpenStackRelationAdapter):

    def __init__(self, relation):
        super(DNSAdapter, self).__init__(relation)

    @property
    def control_listen_ip(self):
        return hookenv.unit_private_ip()

    @property
    def control_ips(self):
        return ';'.join(self.relation.client_ips())

    @property
    def algorithm(self):
        return get_rndc_algorithm()

    @property
    def secret(self):
        return get_rndc_secret()


class BindAdapters(adapters.OpenStackRelationAdapters):
    """
    Adapters class for the Designate charm.
    """
    relation_adapters = {
        'dns_backend': DNSAdapter,
    }

    def __init__(self, relations):
        super(BindAdapters, self).__init__(
            relations)


def set_apparmor():
    apparmor_file = '/etc/apparmor.d/disable/usr.sbin.named'
    if not os.path.isfile(apparmor_file):
        open(apparmor_file, 'w').close()
        host.service_reload('apparmor')


@reactive.when_not('installed')
def install_packages():
    fetch.apt_update()
    fetch.apt_install(BIND_PACKAGES, fatal=True)
    set_apparmor()
    reactive.set_state('installed')


@reactive.when_not('rndckey.available')
def setup_secret():
    if init_rndckey():
        reactive.set_state('rndckey.available')


@reactive.when('rndckey.available')
@reactive.when('dns-backend.related')
def send_info(dns_client):
    dns_client.send_rndckey_info(get_rndc_secret(), get_rndc_algorithm())


@reactive.when('rndckey.available')
@reactive.when('dns-backend.related')
@host.restart_on_change({
    BIND_DIR + '/*': BIND_SERVICES
})
def config_changed(*args):
    set_apparmor()
    adapters = BindAdapters(args)
    for conf in [NAMED_OPTIONS, NAMED_CONF, RNDC_KEY]:
        templating.render(source=conf,
                          target='{}/{}'.format(BIND_DIR, conf),
                          context=adapters)


@reactive.when_not('sync.request.sent')
@reactive.when_not('zones.initialised')
@reactive.when_not('cluster.connected')
@reactive.when('installed')
def setup_sync_target_alone():
    if hookenv.is_leader():
        setup_sync()
        reactive.set_state('zones.initialised')


@reactive.when_not('zones.initialised')
@reactive.when('sync.request.sent')
@reactive.when('cluster.connected')
def update_zones_from_peer(hacluster):
    retrieve_zones(hacluster)


@reactive.when_not('sync.request.sent')
@reactive.when_not('zones.initialised')
@reactive.when('installed')
@reactive.when('cluster.connected')
def check_zone_status(hacluster):
    # This unit has not been initialised yet since zones.initialised has not
    # been set.

    if hookenv.is_leader():
        if get_sync_time():
            # This unit is not the leader but a sync target has already been
            # set suggests this is a new unit which has been nominated as
            # leader early in its lifecycle.
            retrieve_zones()
        else:
            # This unit is the leader and no other unit has set up a sync
            # target then create one since this is a new deployment
            setup_sync()
            reactive.set_state('zones.initialised')
    else:
        request_sync(hacluster)


@reactive.when('zones.initialised')
@reactive.when('cluster.connected')
def process_sync_requests(hacluster):
    if hookenv.is_leader():
        hookenv.log('Processing sync requests', level=hookenv.DEBUG)
        sync_requests = hacluster.retrieve_remote(CLUSTER_SYNC_KEY)
        max_time = 0
        for req in sync_requests:
            if float(req) > max_time:
                max_time = float(req)
        hookenv.log('Newest sync request: {}'.format(max_time),
                    level=hookenv.DEBUG)
        if max_time > float(get_sync_time()):
            setup_sync()
