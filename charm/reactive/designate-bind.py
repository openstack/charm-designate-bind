from charm.openstack.adapters import (
    OpenStackRelationAdapters,
    OpenStackRelationAdapter,
)
from charms.reactive import (
    hook,
    when,
)
from charmhelpers.core.templating import render
from charmhelpers.core.hookenv import unit_private_ip
from charmhelpers.core.host import restart_on_change, service_reload
from charmhelpers.fetch import (
    apt_install,
    apt_update,
)
import os

BIND_DIR = '/etc/bind'
NAMED_OPTIONS = 'named.conf.options'
NAMED_CONF = 'named.conf'
BIND_SERVICES = ['bind9']
BIND_PACKAGES = ['bind9']


class DNSAdapter(OpenStackRelationAdapter):

    def __init__(self, relation):
        super(DNSAdapter, self).__init__(relation)

    @property
    def control_listen_ip(self):
        return unit_private_ip()

    @property
    def control_ips(self):
        return ';'.join(self.relation.client_ips())


class BindAdapters(OpenStackRelationAdapters):
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
        service_reload('apparmor')


@hook('install')
def install_packages():
    apt_update()
    apt_install(BIND_PACKAGES, fatal=True)
    set_apparmor()


@when('dns-backend.related')
def send_info(dns_client):
    dns_client.send_rndckey_info()


@when('dns-backend.related')
@restart_on_change({
    BIND_DIR + '/*': BIND_SERVICES
})
def config_changed(*args):
    set_apparmor()
    adapters = BindAdapters(args)
    for conf in [NAMED_OPTIONS, NAMED_CONF]:
        render(source=conf,
               target='{}/{}'.format(BIND_DIR, conf),
               context=adapters)
