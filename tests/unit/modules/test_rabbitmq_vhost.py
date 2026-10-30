# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.rabbitmq.plugins.modules import rabbitmq_vhost

from ansible_collections.community.rabbitmq.tests.unit.compat.mock import MagicMock, patch
from ansible_collections.community.rabbitmq.tests.unit.modules.utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, set_module_args


class TestRabbitMQVhostModule(ModuleTestCase):
    def setUp(self):
        super(TestRabbitMQVhostModule, self).setUp()
        self.module = rabbitmq_vhost

    def tearDown(self):
        super(TestRabbitMQVhostModule, self).tearDown()

    def _run_with_rabbitmqctl(self, args, run_command, get_bin_path, existing_vhosts=''):
        get_bin_path.return_value = '/rabbitmqctl'
        run_command.side_effect = [(0, existing_vhosts, ''), (0, '', ''), (0, '', '')]
        with set_module_args(args):
            with self.assertRaises(AnsibleExitJson) as result:
                self.module.main()
        return result.exception.args[0], [call[0][0] for call in run_command.call_args_list]

    @patch('ansible.module_utils.basic.AnsibleModule.get_bin_path')
    @patch('ansible.module_utils.basic.AnsibleModule.run_command')
    def test_add_vhost_with_default_queue_type(self, run_command, get_bin_path):
        """add_vhost must be called with --default-queue-type when it is set."""
        result, commands = self._run_with_rabbitmqctl(
            {'name': '/test', 'default_queue_type': 'quorum'}, run_command, get_bin_path)

        assert result['changed'] is True
        assert ['/rabbitmqctl', '-q', '-n', 'rabbit', 'add_vhost', '/test', '--default-queue-type', 'quorum'] in commands

    @patch('ansible.module_utils.basic.AnsibleModule.get_bin_path')
    @patch('ansible.module_utils.basic.AnsibleModule.run_command')
    def test_add_vhost_without_default_queue_type(self, run_command, get_bin_path):
        """add_vhost must not get a queue type argument when it is not set."""
        result, commands = self._run_with_rabbitmqctl({'name': '/test'}, run_command, get_bin_path)

        assert result['changed'] is True
        assert ['/rabbitmqctl', '-q', '-n', 'rabbit', 'add_vhost', '/test'] in commands

    @patch('ansible.module_utils.basic.AnsibleModule.get_bin_path')
    @patch('ansible.module_utils.basic.AnsibleModule.run_command')
    def test_existing_vhost_with_default_queue_type_is_unchanged(self, run_command, get_bin_path):
        """An existing vhost is left alone, default_queue_type only applies on creation."""
        result, commands = self._run_with_rabbitmqctl(
            {'name': '/test', 'default_queue_type': 'quorum'}, run_command, get_bin_path,
            existing_vhosts='/test\tfalse\n')

        assert result['changed'] is False
        assert len(commands) == 1

    def test_invalid_default_queue_type(self):
        """Unknown queue types must be rejected."""
        with self.assertRaises(AnsibleFailJson):
            with set_module_args({'name': '/test', 'default_queue_type': 'invalid'}):
                self.module.main()

    @patch('ansible.module_utils.basic.AnsibleModule.get_bin_path')
    @patch('ansible_collections.community.rabbitmq.plugins.modules.rabbitmq_vhost.requests.request')
    def test_add_vhost_with_default_queue_type_api(self, request, get_bin_path):
        """The management API must receive default_queue_type in the PUT body."""
        get_bin_path.return_value = None
        request.side_effect = [MagicMock(ok=False, status_code=404), MagicMock(ok=True)]

        with set_module_args({
            'name': '/test',
            'default_queue_type': 'stream',
            'login_host': 'localhost',
            'login_user': 'admin',
            'login_password': 'secret',
        }):
            with self.assertRaises(AnsibleExitJson) as result:
                self.module.main()

        assert result.exception.args[0]['changed'] is True
        put_call = request.call_args_list[1]
        assert put_call[1]['method'] == 'put'
        assert put_call[1]['json'] == {'default_queue_type': 'stream'}
