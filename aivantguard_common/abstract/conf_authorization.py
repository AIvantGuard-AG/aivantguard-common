# aivantguard-common/abstract/conf_authorization.py
import logging
from typing import List

logger = logging.getLogger(__name__)


class AuthorizationException(Exception):
    pass


class ConfigurationAuthorization:

    def __init__(self, authorization_template: dict):
        self._authorization = authorization_template

    def check_authorization(self, caller: str,  keys: List[str], operation: str) -> bool:
        # Validate operation is one of CRUD
        valid_operations = ["C", "R", "U", "D"]
        if operation not in valid_operations:
            logger.warning(f"Invalid operation {operation}")
            return False
        if caller not in self._authorization.keys():
            logger.warning(f"{caller} doesn't exist in authorization template!")
            return False
        auth_rules = self._authorization[caller]
        logger.debug("auth_rules", auth_rules)
        # Check each rule
        best_match_auth = None
        best_match_depth = 0
        # Iterate through each authorization rules
        for rule in auth_rules:
            rule_objects = rule["object"]
            authorization = rule["authorization"]
            # Check if the check_key matches or is a subset of the rule's object path
            match_depth = 0
            is_match = True
            # Compare each level of the paths
            for i, key in enumerate(keys):
                if i >= len(rule_objects) or rule_objects[i] != key:
                    is_match = False
                    break
                match_depth = i + 1
            # If we found a match and it's deeper than previous matches
            if is_match and match_depth > best_match_depth:
                best_match_auth = authorization
                best_match_depth = match_depth
            # If no exact match but the rule is a parent path
            elif (len(keys) > len(rule_objects) and
                  all(keys[i] == rule_objects[i] for i in range(len(rule_objects)))):
                if len(rule_objects) > best_match_depth:
                    best_match_auth = authorization
                    best_match_depth = len(rule_objects)
        return operation in best_match_auth

# --- Example Usage (Optional) ---
# To demonstrate how the authorization setup:
# example template
#
#   authorization_template = {
#       "com.example.admintool": [
#           {"object": "*", "authorization": "CRUD"}
#       ],
#       "com.example.clienttool": [
#           {"object": ["client", "tool"], "authorization": "CRUD"},
#           {"object": ["client"], "authorization": "R"}
#       ]
#   }
#
#   In the client program
#   client_authorizations = ConfigurationAuthorization(authorization_template)
#   client_authorizations.check_authhorization(["client"], "U")
