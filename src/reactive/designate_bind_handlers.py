import charms.reactive as reactive
import charmhelpers.core.hookenv as hookenv
import charm.openstack.designate_bind as designate_bind


@reactive.when_not('installed')
def install_packages():
    '''Install charms packages'''
    designate_bind.install()
    designate_bind.set_apparmor()
    reactive.set_state('installed')


@reactive.when_not('rndckey.available')
def setup_secret():
    '''Get the existing rndc key from leader db if one exists else generate a
    new one'''
    if designate_bind.init_rndckey():
        reactive.set_state('rndckey.available')


@reactive.when('rndckey.available')
@reactive.when('dns-backend.related')
def send_info(dns_client):
    '''Send the secret and the algorithm used to encode the key to clients'''
    dns_client.send_rndckey_info(
        designate_bind.get_rndc_secret(),
        designate_bind.get_rndc_algorithm())


@reactive.when('rndckey.available')
@reactive.when('dns-backend.related')
def config_changed(*args):
    '''Render configs and restart services if necessary'''
    designate_bind.set_apparmor()
    designate_bind.render_all_configs(args)


@reactive.when_not('sync.request.sent')
@reactive.when_not('zones.initialised')
@reactive.when_not('cluster.connected')
@reactive.when('installed')
def setup_sync_target_alone():
    '''If this is the only unit in the application then setup a sync target.
    This will likely by empty as zones.initialised is only unset when a unit
    frst comes up but the presence of the target allows subsequent units to
    bootstrap if leadership flips to them as they come up'''
    if hookenv.is_leader():
        designate_bind.setup_sync()
        reactive.set_state('zones.initialised')


@reactive.when_not('zones.initialised')
@reactive.when('sync.request.sent')
@reactive.when('cluster.connected')
def update_zones_from_peer(hacluster):
    '''A sync request has been sent by this unit so check if a peer has
    responded and if so retrieve the zone information and install it'''
    designate_bind.retrieve_zones(hacluster)


@reactive.when_not('sync.request.sent')
@reactive.when_not('zones.initialised')
@reactive.when('installed')
@reactive.when('cluster.connected')
def check_zone_status(hacluster):
    '''This unit has not been initialised yet so request a zones file or
    set an inital sync'''

    if hookenv.is_leader():
        if designate_bind.get_sync_time():
            # This unit is not the leader but a sync target has already been
            # set suggests this is a new unit which has been nominated as
            # leader early in its lifecycle. The leader responds to sync
            # requests and this unit is the leader so not worth sending out a
            # sync request.
            designate_bind.retrieve_zones()
        else:
            # This unit is the leader and no other unit has set up a sync
            # target then create one since this is a new deployment
            designate_bind.setup_sync()
            reactive.set_state('zones.initialised')
    else:
        # If this unit is not the leader as is not yet initialised then request
        # a zones file from a peer
        designate_bind.request_sync(hacluster)


@reactive.when('zones.initialised')
@reactive.when('cluster.connected')
def process_sync_requests(hacluster):
    '''If this unit is the leader process and new sync requests'''
    if hookenv.is_leader():
        designate_bind.process_requests(hacluster)
