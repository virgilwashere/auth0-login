#
# Copyright 2019 - binx.io B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging
import configparser
from collections import namedtuple
import sys  # import platform
from os import chmod, path, environ
import click

AWSCredentials = namedtuple(
    'AWSCredentials', 'access_key secret_key session_token expiration')


def write_aws_credentials(credentials: AWSCredentials, profile: str):
    """Write AWS credentials to ~/.aws/credentials."""
    filename = path.expanduser(path.expandvars('~/.aws/credentials'))
    config = configparser.ConfigParser()
    config.read(filename)
    if not config.has_section(profile):
        config.add_section(profile)
    config.set(profile, 'aws_access_key_id', credentials.access_key)
    config.set(profile, 'aws_secret_access_key', credentials.secret_key)
    if credentials.session_token:
        config.set(profile, 'aws_session_token', credentials.session_token)
    else:
        config.remove_option(profile, 'aws_session_token')
    if credentials.expiration:
        config.set(profile, 'expiration', f'{credentials.expiration}')
    else:
        config.remove_option(profile, 'expiration')
    with open(filename, 'w+') as f:
        try:
            config.write(f)
        finally:
            f.close()
    chmod(filename, 0o600)
    logging.info(f'credentials saved under AWS profile {profile}.')


def export_aws_credentials(credentials: AWSCredentials, profile: str):
    """
    Output commands to set environmental variables.

    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_SECURITY_TOKEN
    AWS_SESSION_EXPIRATION

    """
    envcommand = "export"
    if(sys.platform == "win32"):
        envcommand = "set"
    logging.debug(
        f'Detected {sys.platform} platform with ENV command {envcommand}.')

    logging.info(
        f'Run these commands to export credentials for AWS profile {profile}.')
    # f"""Run these commands to export credentials for AWS profile {profile}.""", err=True)
    click.echo(
        u"""{} AWS_ACCESS_KEY_ID={}""".format(envcommand,
                                              credentials.access_key))
    click.echo(
        u"""{} AWS_SECRET_ACCESS_KEY={}""".format(envcommand,
                                                  credentials.secret_key))
    if credentials.session_token:
        click.echo(
            u"""{} AWS_SESSION_TOKEN={}""".format(envcommand,
                                                  credentials.session_token))
        click.echo(
            u"""{} AWS_SECURITY_TOKEN={}""".format(envcommand,
                                                   credentials.session_token))
    if credentials.expiration:
        click.echo(
            u"""{} AWS_SESSION_EXPIRATION={}""".format(envcommand,
                                               f'{credentials.expiration}'))
