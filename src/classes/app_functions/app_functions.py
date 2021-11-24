import requests
from ..config.config import get_application_config_subject_item
from ..app_settings.app_settings import wdt_version_file, wdt_current_version


def check_update_wdt():
    """ Check for new app version """
    url = wdt_version_file
    try:
        resp = requests.get(url, timeout=2)
    except Exception as e:
        return 'Connection Error', f'{wdt_current_version}'
    if not resp.ok:
        return 'Connection Error', f'{wdt_current_version}'

    latest_version = float(resp.text)
    # new_version = latest_version

    if latest_version <= float(wdt_current_version):
        return 'Latest Version', f'{wdt_current_version}'
    return 'New Version', f'{latest_version}'
