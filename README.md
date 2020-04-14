# Ansible Collection: community.rabbitmq

This repo hosts the `community.rabbitmq` Ansible Collection.

The collection includes the rabbitmq modules and plugins supported by Ansible rabbitmq community to help the management of rabbitmq infrastructure.


## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the rabbitmq community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install community.rabbitmq

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: community.rabbitmq
```

## Testing and Development

If you want to develop new content for this collection or improve what is already here, the easiest way to work on the collection is to clone it into one of the configured `COLLECTIONS_PATHS <https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths>`_, and work on it there.


### Testing with `ansible-test`

TBD

## Publishing New Version

TBD

## More Information

TBD

## Communication

We have a dedicated Working Group for Rabbitmq.
For more information about communities, meetings and agendas see `Rabbitmq Community Wiki <https://github.com/ansible/community/wiki/rabbitmq>`_.

## License

GNU General Public License v3.0 or later

See `LICENSE <https://github.com/ansible-collections/rabbitmq/blob/master/LICENSE>`_ to see the full text.
