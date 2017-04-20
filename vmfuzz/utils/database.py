""" Module handling the communication with the database """
import requests

WEBAPP_IP = ''


def init(config_system):
    """
    Initialize the module

    Args:
        config_system (dict): The system configuration
    """

    global WEBAPP_IP
    WEBAPP_IP = config_system['webapp_ip']


def ask_status(config):
    """
    Ask the statut to the database
    Args:
        config (dict): the user configuration
    Returns:
        string: the status
    """
    try:
        resp = requests.get('http://' + WEBAPP_IP +
                            ':5000/_get_status/' +
                            config['_run_id'])
        return resp.json()['status']
    except:
        return 'ERROR'


def send_status(config, status):
    """
    Ask the statut to the database
    Args:
        config (dict): the user configuration
        status (string): the status to be sent
    """

    url = 'http://%s:5000/_set_status/%s/%s/%s' % (WEBAPP_IP,
                                                   config['_run_id'],
                                                   config['_worker_id'],
                                                   status)
    requests.post(url)


def send_stats(config, data):
    """
    Send the stats to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_stats/%s/%s' % (WEBAPP_IP,
                                               config['_run_id'],
                                               config['_worker_id'])
    requests.post(url, json=data)


def send_targets(config, targets):
    """
    Send the targets to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_targets/%s' % (WEBAPP_IP, config['_program_id'])
    requests.post(url, json={'targets': targets})


def send_classification(config, data):
    """
    Send the results of !exploitable to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_classification/%s' % (WEBAPP_IP,
                                                     config['_program_id'])

    requests.post(url, json=data)


def send_error(config, msg):
    """
    Send the results of !exploitable to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """
    send_status(config, 'ERROR')
    url = 'http://%s:5000/_set_error/%s/%s' % (WEBAPP_IP,
                                               config['_run_id'],
                                               config['_worker_id'])
    requests.post(url, json={'msg': msg})
