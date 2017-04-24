""" Module handling the communication with the database """
import time
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


def post_data(url, data):
    """
    Post data

    Args:
        url (string): url
        data (): data to be sent
    Note:
        If an error occured, wait 5 secs and try\
        again to send the data
    """
    try:
        requests.post(url, json=data)
    except requests.exceptions.RequestException as error:
        print error
        time.sleep(5)
        post_data(url, data)

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
    except requests.exceptions.RequestException as error:
        print "Status received %s" % error
        return 'ERROR'


def send_status(config, status):
    """
    Send the statut to the database
    Args:
        config (dict): the user configuration
        status (string): the status to be sent
    """

    url = 'http://%s:5000/_set_status/%s/%s/%s' % (WEBAPP_IP,
                                                   config['_run_id'],
                                                   config['_worker_id'],
                                                   status)
    post_data(url, None)


def send_exploitable_status(config, status):
    """
    Send the statut to the database
    Args:
        config (dict): the user configuration
        status (string): the status to be sent
    """

    url = 'http://%s:5000/_set_status_exploitable/%s/%s/%s' % (WEBAPP_IP,
                                                               config['_run_id'],
                                                               config['_worker_id'],
                                                               status)
    post_data(url, None)


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
    post_data(url, data)


def send_targets(config, targets):
    """
    Send the targets to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_targets/%s' % (WEBAPP_IP, config['_program_id'])
    post_data(url, {'targets': targets})


def send_classification(config, data):
    """
    Send the results of !exploitable to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """

    url = 'http://%s:5000/_set_classification/%s' % (WEBAPP_IP,
                                                     config['_run_id'])

    post_data(url, data)


def send_error(config, msg):
    """
    Send the results of !exploitable to the database
    Args:
        config (dict): the user configuration
        data (dict): data to be sent
    """
    url = 'http://%s:5000/_set_error/%s/%s' % (WEBAPP_IP,
                                               config['_run_id'],
                                               config['_worker_id'])
    post_data(url, {'msg': msg})
    send_status(config, 'ERROR')
