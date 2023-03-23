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


@reactive.when('zones.initialised')
def assess_status():
    designate_bind.assess_status()


@reactive.when('config.changed.service_ips')
def service_ips_changed():
    """Reconfigure service IPs on the unit."""
    designate_bind.reconfigure_service_ips()


@reactive.when('ha.connected')
def hacluster_connected(_):
    """Check if service IPs are awaiting configuration via hacluster."""
    if reactive.is_flag_set(designate_bind.AWAITING_HACLUSTER_FLAG):
        hookenv.log('hacluster connected, configuring Service IPs',
                    hookenv.INFO)
        designate_bind.reconfigure_service_ips()
        reactive.clear_flag(designate_bind.AWAITING_HACLUSTER_FLAG)


@reactive.when('ha-relation-departed')
def hacluster_departed(_):
    """Set blocked state if hacluster leaves and service_ips are configured."""
    if hookenv.config('service_ips'):
        reactive.set_flag(designate_bind.AWAITING_HACLUSTER_FLAG)
        designate_bind.assess_status()
