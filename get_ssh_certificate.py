#!/bin/python3

import os
import shutil
import tempfile
import time

import click
import paramiko
import qrcode
import requests

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://sshca.deic.dk"
IDP_NAME = "MyAccessIDAcc"


def generate_key_files():
    ssh_temp_folder = tempfile.mkdtemp()
    key_type = "ed25519"

    os.system(f"ssh-keygen -N '' -t {key_type} -f {ssh_temp_folder}/id_{key_type}")

    with open(f"{ssh_temp_folder}/id_{key_type}.pub", 'r') as file:
        pubkey = file.read()

    return ssh_temp_folder, key_type, pubkey

def main():
    #1: Ask SSH CA for more informations regarding the provisioners and choose the one for MyAccessID acc
    response = requests.get(f"{BASE_URL}/www/provisioners.json", verify=False)
    provisioners = response.json()["provisioners"]
    provisioner = next(p for p in provisioners if p["name"] == IDP_NAME)
    #Most important part is the endpoints configuration URL
    config_url = provisioner["configurationEndpoint"]

    #2: From the endpoint configuration, get the address for starting device_code_flow
    provisioner_config = requests.get(config_url).json()
    dev_auth_endpoint = provisioner_config["device_authorization_endpoint"]
    #Get also the client ID from the data provided by SSH CA
    client_id = provisioner["clientID"]

    #3: Contact MyAccessID directly using device_code_flow with the client_id
    response = requests.post(
        dev_auth_endpoint,
        data={
            "client_id": client_id,
            "scope": "openid email profile eduperson_entitlement",
        }
    )
    dev_auth_response = response.json()
    #get back the device code, verification uri and user code
    device_code = dev_auth_response["device_code"]

    #4: Prompt user to access the verification uri (using QR Code or link) with the user code and authenticate
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(dev_auth_response["verification_uri"])
    qr.make(fit=True)
    qr.print_ascii()

    click.echo(f"Scan the QR Code or go to: {dev_auth_response['verification_uri']}")
    click.echo(f"User Code: {dev_auth_response['user_code']}")

    #5: find token endpoint in the configuration from MyAccessID, start polling and wait for user
    token_endpoint = provisioner_config["token_endpoint"]

    try_count = 0
    max_try = 120
    sleep_secs = 2
    #wait till the user authenticate via browser or second device
    while try_count < max_try:
        time.sleep(sleep_secs)
        response = requests.post(
            token_endpoint,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
        )
        if 200 <= response.status_code < 300:
            break

    #6: if everything goes well, get the access_token from MyAccessID
    auth_response = response.json()
    access_token = auth_response["access_token"]

    #7: prepare temporary directories for the work with newly generated ssh keys and certs
    #create temporary folder, generate there a new ssh key (public and private part)
    ssh_temp_folder, key_header, pub_key = generate_key_files()

    #8: Access SSH CA API with public ssh key and access_token
    #asking to sign the ssh key with a proper information about user and return it back
    #the process of configuration of the certificate content is on the SSH CA site
    sign_response = requests.post(
        f"{BASE_URL}/ssh/sign",
        json={
            "PublicKey": pub_key,
            "OTT": access_token,
        },
        verify=False,
    )

    #9: SSH CA provides a new SSH Certificate
    #cert = sign_response.json()["crt"]

    #10: set up the new ssh certificate to the ssh-agent (using ssh-add)
    #Inform user about the success.
    #Clean the environment for the user.
    with open(f"{ssh_temp_folder}/id_{key_header}-cert.pub", mode="w") as f:
        f.write(sign_response.text)

    os.chmod(f"{ssh_temp_folder}/id_{key_header}-cert.pub", 0o600)

    click.echo("Authentication successful! You can now ssh into the client machine.")

    os.system(f"ssh-add -D 2> /dev/null")
    os.system(f"ssh-add {ssh_temp_folder}/id_{key_header} 2> /dev/null")

    shutil.rmtree(ssh_temp_folder)

if __name__ == '__main__':
    main()

