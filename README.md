# EclecticIQ Platform

This implements a custom threat service for [EclecticIQ Platform](https://www.eclecticiq.com/). This threat service is automatically triggered when adding artifacts of types: "net.ip", "net.name", "email", "email.header", "email.header.sender_address", "email.header.to", "hash.md5", "hash.sha1", "hash.sha256", "hash.sha512", "net.uri", "net.uri.path".

To query EclecticIQ Platform user needs to provide EclecticIQ Platform URL, credentials and group name for Sightings creation.

# Prerequisites
Before registering Custom Threat Service with the Resilient platform, verify the following:
1. The Resilient platform is version 28 or later.
2. The Resilient platform can access EclecticIQ platform through HTTPS (port 443 TCP by default).
3. Python 2.7 in the Resillient Platform.
4. You have master administrator account with the Resilient platform.
5. You have access to the command line of the Resilient appliance, which hosts the Resilient platform.
6. You have EclecticIQ Platform deployed and have enough permissions to create users and groups for integration.
7. You have neccesary web components in the Resilient:

```
resilient_circuits
rc-webserver
rc-cts
```

#Register the Threat Service
1. Log in to the Resilient appliance using an SSH client, such as PuTTY as 'resadmin' user.
2. Copy the ZIP file with integration to the appliance using SCP. The file should be copied to the home directory of the ‘resadmin’ user.
3. At the prompt, unzip the integration.   QWE
4. Run following command to install CTS: #python setup.py install
4.a  To install in "development mode": #pip install -e ./rc-cts-eclecticiq-1.0.3/
5. To configure the EclecticIQ Platform settings, run `resilient-circuits config -c` to create configuration or `resilient-circuits config -u` to update.
6. Then edit the `[eclecticiq]` template with the foloowing parameters:
[eclecticiq]
# API credentials
eclecticiq_url=https://eclecticiqhost.localdomain		//address of EclecticIQ Platform
eclecticiq_user=admin									//username for EclecticIQ Platform access
eclecticiq_password=^eclecticiq_password				//password for authentiaction. It's recommended to use res-keyring to store password
eclecticiq_ssl_check=True								//True to check EclecticIQ Platform SSL cert, False to ignore self-signed certs

# Sightings parameters
sightings_auto_creation=True							//if True, Resilient creates Sighting in EclecticIQ Platform back automatically when matches Threat
sightings_group_name=Testing group 						//group name for Sightings Source in EclecticIQ Platfrom

7. Run with: `resilient-circuits run`.
8. To register this custom threat service with Resilient: `sudo resutil threatserviceedit -name "EclecticIQ Platform" -resturl http://<resilient_circuits_url>:9000/cts/eiq`
9. To test this custom threat service with Resilient: `sudo resutil threatservicetest -name "EclecticIQ Platform"`
