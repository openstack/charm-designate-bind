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

import unittest

from unittest import mock

import reactive.designate_bind_handlers as handlers


_when_args = {}
_when_not_args = {}


def mock_hook_factory(d):

    def mock_hook(*args, **kwargs):

        def inner(f):
            # remember what we were passed.  Note that we can't actually
            # determine the class we're attached to, as the decorator only gets
            # the function.
            try:
                d[f.__name__].append(dict(args=args, kwargs=kwargs))
            except KeyError:
                d[f.__name__] = [dict(args=args, kwargs=kwargs)]
            return f
        return inner
    return mock_hook


class TestDesignateHandlers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._patched_when = mock.patch('charms.reactive.when',
                                       mock_hook_factory(_when_args))
        cls._patched_when_started = cls._patched_when.start()
        cls._patched_when_not = mock.patch('charms.reactive.when_not',
                                           mock_hook_factory(_when_not_args))
        cls._patched_when_not_started = cls._patched_when_not.start()
        # force requires to rerun the mock_hook decorator:
        # try except is Python2/Python3 compatibility as Python3 has moved
        # reload to importlib.
        try:
            reload(handlers)
        except NameError:
            import importlib
            importlib.reload(handlers)

    @classmethod
    def tearDownClass(cls):
        cls._patched_when.stop()
        cls._patched_when_started = None
        cls._patched_when = None
        cls._patched_when_not.stop()
        cls._patched_when_not_started = None
        cls._patched_when_not = None
        # and fix any breakage we did to the module
        try:
            reload(handlers)
        except NameError:
            import importlib
            importlib.reload(handlers)

    def setUp(self):
        self._patches = {}
        self._patches_start = {}

    def tearDown(self):
        for k, v in self._patches.items():
            v.stop()
            setattr(self, k, None)
        self._patches = None
        self._patches_start = None

    def patch(self, obj, attr, return_value=None):
        mocked = mock.patch.object(obj, attr)
        self._patches[attr] = mocked
        started = mocked.start()
        started.return_value = return_value
        self._patches_start[attr] = started
        setattr(self, attr, started)

    def test_registered_hooks(self):
        # test that the hooks actually registered the relation expressions that
        # are meaningful for this interface: this is to handle regressions.
        # The keys are the function names that the hook attaches to.
        when_patterns = {
            'setup_sync_target_alone': [('installed', )],
            'send_info': [
                ('dns-backend.related', ),
                ('rndckey.available', ),
            ],
            'config_changed': [
                ('dns-backend.related', ),
                ('rndckey.available', ),
            ],
            'update_zones_from_peer': [
                ('cluster.connected', ),
                ('sync.request.sent', ),
            ],
            'check_zone_status': [
                ('cluster.connected', ),
                ('installed', ),
            ],
            'process_sync_requests': [
                ('cluster.connected', ),
                ('zones.initialised', ),
            ],
            'assess_status': [('zones.initialised', )],
        }
        when_not_patterns = {
            'install_packages': [('installed', )],
            'setup_secret': [('rndckey.available', )],
            'update_zones_from_peer': [('zones.initialised', )],
            'setup_sync_target_alone': [
                ('cluster.connected', ),
                ('zones.initialised', ),
                ('sync.request.sent', ),
            ],
            'check_zone_status': [
                ('zones.initialised', ),
                ('sync.request.sent', ),
            ],
        }
        # check the when hooks are attached to the expected functions
        for t, p in [(_when_args, when_patterns),
                     (_when_not_args, when_not_patterns)]:
            for f, args in t.items():
                # check that function is in patterns
                print(f)
                self.assertTrue(f in p.keys())
                # check that the lists are equal
                newlist = [a['args'] for a in args]
                self.assertEqual(newlist, p[f])

    def test_install_packages(self):
        self.patch(handlers.designate_bind, 'install')
        self.patch(handlers.designate_bind, 'set_apparmor')
        self.patch(handlers.reactive, 'set_state')
        handlers.install_packages()
        self.install.assert_called_once_with()
        self.set_apparmor.assert_called_once_with()
        self.set_state.assert_called_once_with('installed')

    def test_setup_secret(self):
        self.patch(handlers.designate_bind, 'init_rndckey')
        self.patch(handlers.reactive, 'set_state')
        self.init_rndckey.return_value = None
        handlers.setup_secret()
        self.assertFalse(self.set_state.called)
        self.init_rndckey.return_value = 'secret'
        handlers.setup_secret()
        self.set_state.assert_called_with('rndckey.available')

    def test_setup_info(self):
        dnsclient = mock.MagicMock()
        self.patch(handlers.designate_bind, 'get_rndc_secret')
        self.patch(handlers.designate_bind, 'get_rndc_algorithm')
        self.get_rndc_secret.return_value = 'secret'
        self.get_rndc_algorithm.return_value = 'hmac-md5'
        handlers.send_info(dnsclient)
        dnsclient.send_rndckey_info.assert_called_once_with(
            'secret',
            'hmac-md5')

    def test_config_changed(self):
        self.patch(handlers.designate_bind, 'set_apparmor')
        self.patch(handlers.designate_bind, 'render_all_configs')
        handlers.config_changed('arg1', 'arg2')
        self.set_apparmor.assert_called_once_with()
        self.render_all_configs.assert_called_once_with(('arg1', 'arg2', ))

    def test_setup_sync_target_alone(self):
        self.patch(handlers.hookenv, 'is_leader')
        self.patch(handlers.designate_bind, 'setup_sync')
        self.patch(handlers.reactive, 'set_state')
        self.is_leader.return_value = False
        handlers.setup_sync_target_alone()
        self.assertFalse(self.setup_sync.called)
        self.assertFalse(self.set_state.called)
        self.is_leader.return_value = True
        handlers.setup_sync_target_alone()
        self.setup_sync.assert_called_once_with()
        self.set_state.assert_called_once_with('zones.initialised')

    def test_update_zones_from_peer(self):
        self.patch(handlers.designate_bind, 'retrieve_zones')
        handlers.update_zones_from_peer('hacluster')
        self.retrieve_zones.assert_called_once_with('hacluster')

    def test_check_zone_status(self):
        self.patch(handlers.hookenv, 'is_leader')
        self.patch(handlers.reactive, 'set_state')
        self.patch(handlers.designate_bind, 'get_sync_time')
        self.patch(handlers.designate_bind, 'retrieve_zones')
        self.patch(handlers.designate_bind, 'setup_sync')
        self.patch(handlers.designate_bind, 'request_sync')
        # Leader test: Retrieve sync
        self.is_leader.return_value = True
        self.get_sync_time.return_value = 100
        handlers.check_zone_status('hacluster')
        self.retrieve_zones.assert_called_once_with()
        self.retrieve_zones.reset_mock()
        # Leader test: Setup sync
        self.is_leader.return_value = True
        self.get_sync_time.return_value = None
        handlers.check_zone_status('hacluster')
        self.assertFalse(self.retrieve_zones.called)
        self.setup_sync.assert_called_once_with()
        self.set_state.assert_called_once_with('zones.initialised')
        # Non-Leader test
        self.is_leader.return_value = False
        handlers.check_zone_status('hacluster')
        self.request_sync.assert_called_once_with('hacluster')

    def test_process_sync_requests(self):
        self.patch(handlers.hookenv, 'is_leader')
        self.patch(handlers.designate_bind, 'process_requests')
        self.is_leader.return_value = False
        handlers.process_sync_requests('hacluster')
        self.assertFalse(self.process_requests.called)
        self.process_requests.reset_mock()
        self.is_leader.return_value = True
        handlers.process_sync_requests('hacluster')
        self.process_requests.assert_called_once_with('hacluster')
