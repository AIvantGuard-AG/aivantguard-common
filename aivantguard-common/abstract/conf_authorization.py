# aivantguard-common/abstract/conf_authorization.py
from dataclasses import dataclass
from typing import Union, List


@dataclass(frozen=True)
class AuthorizationOperation:
    C: "C"     # Create
    R: "R"     # Read
    U: "U"     # Update
    D: "D"     # Delete


class AuthorizationException(Exception):
    pass


class ConfigurationAuthorization:

    def __init__(self, authorization_template: dict):
        self._authorization = authorization_template

    def check_authorization(self, caller: Union[str, List[str]], operation: str) -> bool:
        # Convert single string caller to list for consistent handling
        if isinstance(caller, str):
            caller = [caller]

        # Validate operation is one of CRUD
        valid_operations = {AuthorizationOperation.C,
                            AuthorizationOperation.R,
                            AuthorizationOperation.U,
                            AuthorizationOperation.D}
        if operation not in valid_operations:
            return False

        # Check if caller exists in authorization template
        if isinstance(caller, list) and len(caller) > 0:
            caller_key = caller[0]
        else:
            return False

        if caller_key not in self._authorization:
            return False

        # Get authorization rules for this caller
        auth_rules = self._authorization[caller_key]

        # Check each rule
        for rule in auth_rules:
            rule_object = rule["object"]
            auth_string = rule["authorization"]

            # Convert wildcard or single string to list for consistent handling
            if rule_object == "*":
                return operation in auth_string
            elif isinstance(rule_object, str):
                rule_object = [rule_object]

            # Check if the caller path matches or is a subpath of rule_object
            if len(rule_object) <= len(caller):
                matches = True
                for i, segment in enumerate(rule_object):
                    if segment != caller[i]:
                        matches = False
                        break
                if matches:
                    return operation in auth_string
        return False

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
#           {"object": ["client"], "authorization", "R"}
#       ]
#   }
#
#   In the client program
#   client_authorizations = ConfigurationAuthorization(authorization_template)
#   client_authorizations.check_authhorization(["client"], "U")
