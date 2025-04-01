# aivantguard_common/utility/configtool.py
import base64
import inspect
import json
import logging
import os
import threading
from abc import abstractmethod
from typing import List, Any
from aivantguard_common.utility import advanced_encrypt
from aivantguard_common.abstract.conf_authorization import ConfigurationAuthorization


logger = logging.getLogger(__name__)


class ConfigurationTool:

    def __init__(self, authorization_template: ConfigurationAuthorization, configuration_path: str, encryption_password: str):
        self._lock = threading.Lock()
        self._authorization_template = authorization_template
        self._configuration_path = configuration_path
        self._encryption_password = encryption_password
        self._configuration = None
        self._load_configuration()
        self.populate_configuration()
        logger.info("Configuration loaded...")

    def _load_configuration(self):
        try:
            if os.path.exists(self._configuration_path):
                with self._lock:
                    with open(self._configuration_path, "rb") as f:
                        _config_bytes = f.read()
                    _salt = _config_bytes[0:64]
                    _config_cipherbytes = _config_bytes[64:]
                    _aeskey = advanced_encrypt.derive_key_from_password(self._encryption_password, _salt, key_length=64)
                    _decrypted_config = advanced_encrypt.aes_gcm_hmac_decrypt(_aeskey, _config_cipherbytes)
                    self._configuration = json.loads(base64.b64decode(_decrypted_config).decode())
            else:
                self._configuration = {}
                self.save_configuration()
            logger.info("Configuration loaded successfully...")
        except Exception as e:
            logger.error(f"Error while loading configuration: {e}")

    def save_configuration(self):
        try:
            _salt = advanced_encrypt.generate_salt(64)
            _aeskey = advanced_encrypt.derive_key_from_password(self._encryption_password, _salt, key_length=64)
            with self._lock:
                _config_bytes = base64.b64encode(json.dumps(self._configuration).encode())
                _cipher_text = advanced_encrypt.aes_gcm_hmac_encrypt(_aeskey, _config_bytes)
                with open(self._configuration_path, "wb") as f:
                    f.write(_salt + _cipher_text)
                logger.info("Configuration saved...")
        except Exception as e:
            logger.exception(f"Error while saving configuration: {e}")

    @staticmethod
    def _get_caller_path() -> str:
        """Construct caller """
        return inspect.currentframe().f_back.f_back.f_code.co_filename.replace(f"{os.getcwd()}/", "")


    def get_configuration_value(self, keys: List[str] | str) -> Any:
        # Get caller path with cwd
        caller_path = self._get_caller_path()
        # Normalize keys to list
        if isinstance(keys, str):
            keys = [keys]
        # Check authorization with constructed path
        if not self._authorization_template.check_authorization(caller_path, keys, "R"):
            logger.warning(f"Unauthorized read attempt by {caller_path} for keys {keys}")
            return None
        try:
            current = self._configuration
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError) as e:
            logger.debug(f"Configuration value not found for keys {keys}: {e}")
            return None

    def update_configuration_value(self, keys: List[str], value: Any) -> bool:
        # Get caller path with cwd
        caller_path = self._get_caller_path()
        # Check authorization with constructed path
        if not self._authorization_template.check_authorization(caller_path, keys, "U"):
            logger.warning(f"Unauthorized update attempt by {caller_path} for keys {keys}")
            return False
        # Update configuration
        try:
            with self._lock:
                current = self._configuration
                # Traverse to the parent of the final key
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                # Set the final key's value
                current[keys[-1]] = value
                self.save_configuration()
                logger.info(f"Configuration updated for keys {keys}")
                return True
        except Exception as e:
            logger.error(f"Error updating configuration for keys {keys}: {e}")
            return False

    def delete_configuration_value(self, keys: List[str]) -> bool:
        # Get caller path with cwd
        caller_path = self._get_caller_path()

        # Check authorization with constructed path
        if not self._authorization_template.check_authorization(caller_path, keys, "D"):
            logger.warning(f"Unauthorized delete attempt by {caller_path} for keys {keys}")
            return False

        # Delete configuration value
        try:
            with self._lock:
                current = self._configuration
                # Traverse to the parent of the final key
                for key in keys[:-1]:
                    if key not in current:
                        return False
                    current = current[key]
                # Delete the final key
                if keys[-1] in current:
                    del current[keys[-1]]
                    self.save_configuration()
                    logger.info(f"Configuration deleted for keys {keys}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting configuration for keys {keys}: {e}")
            return False

    @abstractmethod
    def populate_configuration(self):
        raise NotImplemented("Implement this method!")
