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
"""Get AWS credentials using the obtained SAML token."""

from sys import stdout
from os import environ
import click

from auth0_login import fatal, setting
from auth0_login.aws.console import open_aws_console
from auth0_login.aws.credentials import write_aws_credentials
from auth0_login.aws.credentials import export_aws_credentials
from auth0_login.aws.account import aws_accounts
from auth0_login.aws.saml_assertion import AWSSAMLAssertion
from auth0_login.saml import SAMLGetAccessTokenCommand


class AWSSTSGetCredentialsFromSAMLCommand(SAMLGetAccessTokenCommand):
    """
    Get AWS credentials using the obtained SAML token.

    As multiple AWS roles may have been granted to the SAML token,
    the caller has to specify the `account` number and `role` name to
    generate the credentials for. If you are unsure which accounts
    and roles have been granted, use the `--show` option

    The temporary credentials are stored in `~/.aws/credentials` under
    the specified `profile` name.

    Display the shell commands to export the environment with `--export`.

    By specifying `--open-console` it will open the AWS console too.
    """

    def __init__(self, account, role, profile, export):
        """Initialise the SAML assertion.."""
        super(AWSSTSGetCredentialsFromSAMLCommand, self).__init__()
        self.account = account if account else setting.attributes.get(
            'aws_account')
        if not account and self.account:
            self.account = aws_accounts.get_account(self.account).number

        self.role = role if role else setting.attributes.get('aws_role')
        self.profile = profile if profile else setting.attributes.get(
            'aws_profile')
        self.export = export
        self.open_console = setting.attributes.get('aws_console', False)
        self.saml_response: AWSSAMLAssertion = None

    def set_saml_response(self, saml_response):
        """Assert SAML response."""
        self.saml_response = AWSSAMLAssertion(saml_response)

    def print_roles(self):
        """Print available roles to stdout."""
        for role in self.saml_response.available_roles():
            account = aws_accounts.get_account(role.account)
            stdout.write(f'[{role.name}@{account.alias}]\n')
            stdout.write(f'idp_url = {setting.IDP_URL}\n')
            stdout.write(f'client_id = {setting.CLIENT_ID}\n')
            stdout.write(f'aws_account = {account.alias}\n')
            stdout.write(f'aws_role = {role.name}\n')
            stdout.write(f'aws_profile = {role.name}@{account.alias}\n\n')

    def show_account_roles(self):
        """Request authorization and print available roles."""
        self.request_authorization()
        self.print_roles()

    @property
    def role_arn(self):
        """AWS role ARN."""
        return f'arn:aws:iam::{self.account}:role/{self.role}'

    def run(self):
        """Run AWSSTSGetCredentialsFromSAMLCommand."""
        if not (self.account and self.role and self.profile):
            fatal('--account, --role and --profile are required.')

        self.request_authorization()

        credentials = self.saml_response.assume_role(
            self.role_arn, setting.ROLE_DURATION)
        write_aws_credentials(credentials, self.profile)
        if self.export:
            export_aws_credentials(credentials, self.profile)
        if self.open_console:
            open_aws_console(self.profile)


@click.command('aws-assume-role',
               help=AWSSTSGetCredentialsFromSAMLCommand.__doc__)
@click.option('--account', help='aws account number or alias')
@click.option('--role', help='to assume using the token')
# @click.option('--profile', help='to store the credentials under')
@click.option('--profile',
              default=environ.get('AWS_DEFAULT_PROFILE', 'default'),
              help='awscli profile that will be authenticated. After\n'
              'successful authentication just use:\n'
              '`aws --profile <authenticated profile> <service> ...`',
              )
@click.option('-e', '--export',
              is_flag=True,
              default=False,
              help='Output commands to set environmental variables for\n'
              '{profile} instead of saving them to ~/.aws/credentials.')
@click.option('--show',
              is_flag=True,
              default=False,
              help='account roles available to assume')
@click.option('--open-console', '-C',
              count=True,
              help=' after credential refresh')
def assume_role_with_saml(account, role, profile, export, show, open_console):
    """Get AWS STS credentials using the obtained SAML token."""
    aws_account = aws_accounts.get_account(account).number if account else None
    cmd = AWSSTSGetCredentialsFromSAMLCommand(
        aws_account,
        role,
        profile,
        export)
    if show:
        cmd.show_account_roles()
    else:
        # if export:
        #     self.export_environment = True
        if open_console:
            cmd.open_console = True
        cmd.run()
