================================
Community.Rabbitmq Release Notes
================================

.. contents:: Topics


v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after release 1.0.3.

Bugfixes
--------

- rabbitmq_policy - The ``_policy_check`` piece of the policy module (``policy_data``) is typically list based on a split of the variable ``policy``. However ``policy`` in some cases does not contain data. The fix allows ``tags`` to attempt to load as json first but in the case of failure, assign ``tags`` without using the json loader (https://github.com/ansible-collections/community.rabbitmq/pull/28).

New Modules
-----------

- community.rabbitmq.rabbitmq_feature_flag - Enables feature flag
- community.rabbitmq.rabbitmq_upgrade - Execute rabbitmq-upgrade commands
- community.rabbitmq.rabbitmq_user_limits - Manage RabbitMQ user limits

v1.0.0
======

Minor Changes
-------------

- rabbitmq_publish - Support for connecting with SSL certificates.

Bugfixes
--------

- Refactor RabbitMQ user module to first check the version of the daemon and then, when possible add flags to `rabbitmqctl` so that a machine readable  output is returned. Also, depending on the version, parse the output in correctly. Expands tests accordingly. (https://github.com/ansible/ansible/issues/48890)
- rabbitmq lookup plugin - Fix for rabbitmq lookups failing when using pika v1.0.0 and newer.
- rabbitmq_publish - Fix to ensure the module works correctly for pika v1.0.0 and later. (https://github.com/ansible/ansible/pull/61960)
