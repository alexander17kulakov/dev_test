# -*- coding: utf-8 -*-

from __future__ import print_function


def config_section_data():
    """Produce the default configuration section for app.config,
       when called by `resilient-circuits config [-c|-u]`
    """
    config_data = u"""[eclecticiq]
    
# API credentials
eclecticiq_url=https://eclecticiq.localhost
eclecticiq_user=user
eclecticiq_password=^eclecticiq_password
eclecticiq_ssl_check=True

# Sightings parameters
sightings_auto_creation=True
sightings_group_name=Testing Group

    """
    return config_data
