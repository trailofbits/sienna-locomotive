""" Module handling the communication with the database """

import requests

DATABASE = ''

# TODO JF : Use the real id (worker_id, program_id, ...)

def init(config_system):
    """
    Initialize the module

    Args:
        config_system (dict): The system configuration
    """

    global DATABASE
    DATABASE = config_system['database_ip']

def ask_status(config):
    """
    Ask the statut to the database
    Args:
        config (dict): the user configuration
    Returns:
        string: the status
    """
    try:
        resp = requests.get('http://'+DATABASE+':5000/_get_status/' + config['_id'])
        return resp.json()['status']
    except:
        return 'ERROR'

def send_stats(config, data):
    """
    Send the stats to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_stats/%s/%s' % (DATABASE, config['_id'], config['_id'])
    requests.post(url, data=data)

def send_targets(config, targets):
    """
    Send the targets to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_targets/%s' % (DATABASE, config['_id'])
    requests.post(url, data=targets)

def send_classification(config, data):
    """
    Send the targets to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_classification/%s' % (DATABASE, config['_id'])
    requests.post(url, data=data)
