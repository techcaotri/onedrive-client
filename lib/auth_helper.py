#  Copyright 2019-2024 Jareth Lomson <jareth.lomson@gmail.com>
#  This file is part of OneDrive Client Program which is released under MIT License
#  See file LICENSE for full license details

import logging
import yaml
from requests_oauthlib import OAuth2Session
import os
import time
import json
import msal
import urllib.parse
import shutil

lg = logging.getLogger("odc.auth")

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"
os.environ["OAUTHLIB_IGNORE_SCOPE_CHANGE"] = "1"


class TokenRecorder:
    """ Class that permits to store Azure token """
    def __init__(self, filename, settings_path=None):
        self.filename = filename
        self.token = None
        self.__cache = None
        
        self.default_settings_path = os.path.expanduser("~/.config/odc/oauth_settings.yml")
        self._ensure_settings_file(settings_path)
        self.settings = self._load_settings()
        
        self.authorize_url = f"{self.settings['authority']}{self.settings['authorize_endpoint']}"
        self.token_url = f"{self.settings['authority']}{self.settings['token_endpoint']}"
        self.redirect_url = self.settings['redirect']
        self.scopes_app = self.settings['scopes'].split()

    def _ensure_settings_file(self, provided_settings_path):
        if not os.path.exists(self.default_settings_path):
            if provided_settings_path is None:
                raise FileNotFoundError(f"Settings file not found at {self.default_settings_path} and no alternative path provided.")
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.default_settings_path), exist_ok=True)
            
            # Copy the provided settings file to the default location
            shutil.copy2(provided_settings_path, self.default_settings_path)
            lg.info(f"Copied settings from {provided_settings_path} to {self.default_settings_path}")

    def _load_settings(self):
        with open(self.default_settings_path, 'r') as stream:
            return yaml.load(stream, yaml.SafeLoader)

    def get_token_interactivaly(self, prefix_url, prompt_url_callback):
        self.__cache = msal.SerializableTokenCache()
        app = msal.ConfidentialClientApplication(
            self.settings["app_id"],
            authority=self.settings["authority"],
            client_credential=self.settings["app_secret"],
            token_cache=self.__cache,
        )
        dict_auth = app.initiate_auth_code_flow(
            scopes=self.scopes_app, redirect_uri=self.redirect_url
        )
        print(f"{prefix_url}{dict_auth['auth_uri']}")
        resp = input(prompt_url_callback)
        try:
            if len(resp) > len(self.redirect_url):
                resp = resp[
                    (len(self.redirect_url) + 1) :
                ]  # +1 to consume the char "?"
            print(f"resp={resp}")
            dict_resp = urllib.parse.parse_qs(resp)
        except Exception as e:
            lg.error(f"Error during parsing of callback url - {e}")
            return False
        for key_dict in dict_resp:
            dict_resp[key_dict] = dict_resp[key_dict][0]
        result = app.acquire_token_by_auth_code_flow(
            auth_code_flow=dict_auth, auth_response=dict_resp
        )
        return "access_token" in result

    def store_token(self):
        if self.__cache is not None and self.__cache.has_state_changed:
            lg.debug(f"[store_token]Store in file {self.filename}")
            open(self.filename, "w").write(self.__cache.serialize())
        else:
            lg.error("[store_token]No need to store token")

    def __refresh_token(self, token):
        lg.debug("Refresh token")
        self.init_token_from_file()
        self.store_token()

    def token_exists(self):
        return self.token is not None

    def init_token_from_file(self):
        lg.debug("Init token from file")
        try:
            self.__cache = msal.SerializableTokenCache()
            if os.path.exists(self.filename):
                with open(self.filename, "r") as f:
                    self.__cache.deserialize(f.read())
            app = msal.ConfidentialClientApplication(
                self.settings["app_id"],
                authority=self.settings["authority"],
                client_credential=self.settings["app_secret"],
                token_cache=self.__cache,
            )
            accounts = app.get_accounts()
            chosen = accounts[0]
            self.token = app.acquire_token_silent(self.scopes_app, account=chosen)
        except Exception as err:
            lg.warn(f"Error during file loading {self.filename} - {err}")

    def get_session_from_token(self):
        lg.debug("Get session from token starting")
        refresh_params = {
            "client_id": self.settings["app_id"],
            "client_secret": self.settings["app_secret"],
        }
        client = OAuth2Session(
            self.settings["app_id"],
            token=self.token,
            scope=self.settings["scopes"],
            redirect_uri=self.settings["redirect"],
            auto_refresh_url=self.token_url,
            auto_refresh_kwargs=refresh_params,
            token_updater=self.__refresh_token,
        )
        return client
