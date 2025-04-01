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


class ConfigAuthorization:

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
                _config_bytes = open(self._configuration_path, "rb").read()
                _salt = _config_bytes[0:32]
                _config_cipherbytes = _config_bytes[32:]
                _aeskey = advanced_encrypt.derive_key_from_password(self._encryption_password, _salt)
                _decrypted_config = advanced_encrypt.aes_gcm_hmac_decrypt(_config_cipherbytes, _aeskey)
                self._configuration = json.loads(_decrypted_config)
            else:
                self._configuration = {}
                self.save_configuration()
            logger.info("Configuration loaded successfully...")
        except Exception as e:
            logger.error(f"Error while loading configuration: {e}")

    def save_configuration(self):
        try:
            _salt = advanced_encrypt.generate_salt(32)
            _aeskey = advanced_encrypt.derive_key_from_password(self._encryption_password, _salt)
            with self._lock:
                _config_bytes = base64.b64encode(json.dumps(self._configuration).encode())
                _cipher_text = advanced_encrypt.aes_gcm_hmac_encrypt(_config_bytes, _aeskey)
                with open(self._configuration_path, "wb") as f:
                    f.write(_salt + _cipher_text)
                logger.info("Configuration saved...")
        except Exception as e:
            logger.exception(f"Error while saving configuration: {e}")

    @staticmethod
    def _get_caller_path() -> str:
        """Construct caller path using current working directory and module name."""
        # Get current working directory
        cwd = os.getcwd()
        # Convert to a simplified path-like string (replace separators with dots)
        cwd_parts = cwd.split(os.sep)
        # Filter out empty parts and make it a valid path identifier
        cwd_base = '.'.join(part for part in cwd_parts if part)

        # Get the caller's module name
        caller_frame = inspect.currentframe().f_back.f_back  # Go back two frames
        module_name = inspect.getmodule(caller_frame).__name__

        # Combine cwd with module name
        if module_name == "__main__":
            # For main module, use just the cwd-based path
            return cwd_base
        else:
            # Combine cwd with module name
            return f"{cwd_base}.{module_name}"

    def get_configuration_value(self, keys: List[str] | str) -> Any:
        # Get caller path with cwd
        caller_path = self._get_caller_path()

        # Normalize keys to list
        if isinstance(keys, str):
            keys = [keys]

        # Check authorization with constructed path
        if not self._authorization_template.check_authorization(caller_path, "R"):
            logger.warning(f"Unauthorized read attempt by {caller_path} for keys {keys}")
            return None

        # Traverse configuration dictionary
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
        if not self._authorization_template.check_authorization(caller_path, "U"):
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
        if not self._authorization_template.check_authorization(caller_path, "D"):
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
