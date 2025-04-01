import logging
import os.path
import traceback
import unittest
import uuid

from aivantguard_common.abstract.conf_authorization import ConfigurationAuthorization
from aivantguard_common.utility.configtool import ConfigurationTool

config_authorization = ConfigurationAuthorization({
    "tests/configtool_tests.py": [
        {"object": ["instance_id"], "authorization": "CR"}
    ]
})


class Configuration(ConfigurationTool):

    def __init__(self):
        if not os.path.exists("temp"):
            os.makedirs("temp")
        super().__init__(config_authorization, "temp/config.bin", "secret_password")

    def populate_configuration(self):
        if not self._configuration.get("instance_id"):
            self._configuration["instance_id"] = uuid.uuid4().hex
            self.save_configuration()


class ConfigtoolTests(unittest.TestCase):
    def test_configtool(self):
        try:
            configuration = Configuration()
            assert configuration.get_configuration_value("instance_id"), "Instance id not found in configuration"
            print("Instanceid found in configuration")
        except Exception as e:
            if os.path.exists("temp/config.bin"):
                os.remove("temp/config.bin")
            traceback.print_exc()
            logging.exception("Error while testing configuration")
            self.fail(e)


if __name__ == '__main__':
    unittest.main()
