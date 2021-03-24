import os
import oauthenticator
import datetime
import time
import requests
from requests.exceptions import HTTPError
from traitlets import (
    Integer,
    Unicode,
)
from textwrap import dedent
import json

class InfinAuth(oauthenticator.generic.GenericOAuthenticator):

    client_id = Unicode(
        "xxx_client_id_must_be_specified_xxx",
        config=True,
        help=dedent(
            """
            Cognito client_id
            """
        )
    )

    client_secret = Unicode(
        "xxx_client_secret_must_be_specified_xxx",
        config=True,
        help=dedent(
            """
            Cognito client_secret
            """
        )
    )

    def _create_auth_state(self, token_response, user_data_response):
        self.log.info("InfinAuth._create_auth_state: Entered")
        access_token = token_response['access_token']
        id_token = token_response['id_token']
        refresh_token = token_response.get('refresh_token', None)
        scope = token_response.get('scope', '')
        if isinstance(scope, str):
            scope = scope.split(' ')

        return {
            'access_token': access_token,
            'id_token': id_token,
            'refresh_token': refresh_token,
            'oauth_user': user_data_response,
            'scope': scope,
            'token_time_epoch_seconds': str(int(time.time())),
        }

    async def pre_spawn_start(self, user, spawner):
        self.log.info("InfinAuth.pre_spawn_start: user=" + str(user) + ", spawner=" + str(spawner))
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            self.log.info("InfinAuth.pre_spawn_start: auth_state not enabled")
            return
        else:
            self.spawner = spawner
            spawner.set_auth_state(self.client_id, auth_state['access_token'],
                    auth_state['id_token'], auth_state['refresh_token'])

    async def refresh_user(self, user, handler=None):
        self.log.info("InfinAuth.refresh_user: Entered")
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            self.log.info("infinAuth.refresh_user: auth_state not enabled. Forcing re-login")
            return False
        if ('token_time_epoch_seconds' in auth_state):
            token_time = int(auth_state['token_time_epoch_seconds'])
            self.log.info('InfinAuth.refresh_user: token_time=' + str(token_time))
            time_now = int(time.time())
            if ((token_time + (10 * 60)) < time_now):
                self.log.info('InfinAuth.refresh_user: token has expired. Calling renew_token')
                return self.renew_token(auth_state)
            else:
                return True
        else:
            return self.renew_token(auth_state)

    def renew_token(self, auth_state):
        url = 'https://cognito-idp.us-east-1.amazonaws.com:443/'

        pld = {}
        pld['AuthParameters'] = { "REFRESH_TOKEN": auth_state['refresh_token'], "SECRET_HASH": self.client_secret }
        pld['AuthFlow'] = 'REFRESH_TOKEN_AUTH'
        pld['ClientId'] = self.client_id
        payload = json.dumps(pld)
        self.log.info('renew_token: payload=' + payload)

        headers = {
            'Content-Type': 'application/x-amz-json-1.1',
            'X-Amz-Target' : 'AWSCognitoIdentityProviderService.InitiateAuth'
            }

        try:
            response = requests.post(url, data=payload, headers=headers)
            response.raise_for_status()
        except HTTPError as http_err:
            self.log.error(f'HTTP error occurred: {http_err}')
            raise
        except Exception as err:
            self.log.error(f'Other error occurred: {err}')
            raise
        else:
            authres = response.json()['AuthenticationResult']
            self.log.info('InfinAuth.renew_token: authres=' + str(authres))
            id_token = authres['IdToken']
            access_token = authres['AccessToken']
            token_time = int(time.time())
            # modify incoming auth_state and return it
            auth_state['access_token'] = access_token
            auth_state['id_token'] = id_token
            auth_state['token_time_epoch_seconds'] = str(token_time)
            try:
                self.spawner.set_auth_state(self.client_id, auth_state['access_token'], auth_state['id_token'], auth_state['refresh_token'])
            except AttributeError:
                self.log.info('InfinAuth.renew_token: WARNING could not set auth state in spawner ')
            return { 'auth_state': auth_state }
