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

import click

from auth0_login import fatal
from auth0_login.aws import assume_role_with_saml
from auth0_login.config import setting
from auth0_login.saml import get_saml_token


@click.group(
    name='saml-login',
    help="A command line utility to obtain SAML tokens and AWS credentials.")
@click.option('--verbose',
              is_flag=True,
              default=False,
              help=' for tracing purposes')
@click.option('--configuration', '-c',
              default="DEFAULT",
              help='configured in .saml-login to use')
def cli(verbose, configuration):
    logging.basicConfig(
        format='%(levelname)s:%(message)s',
        level=(logging.DEBUG if verbose else logging.INFO))
    setting.filename = '.saml-login'
    setting.SECTION = configuration
    if not setting.exists:
        fatal('no configuration %s found in %s', configuration,
              setting.filename)


cli.add_command(get_saml_token)
cli.add_command(assume_role_with_saml)

if __name__ == '__main__':
    cli()
