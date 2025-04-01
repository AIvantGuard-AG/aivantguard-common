# tests/test_authorizationrules.py
import unittest

from aivantguard_common.abstract.conf_authorization import ConfigurationAuthorization

test_authorization = ConfigurationAuthorization({
    "tests/configtool_tests.py": [
        {"object": ["instance_id"], "authorization": "CR"},
        {"object": ["test"], "authorization": "R"},
        {"object": ["test", "test_level2"], "authorization": "CRUD"},
    ]
})


class MyTestCase(unittest.TestCase):

    def test_something(self):
        try:
            # TEST01
            print("CHECKING IF A PROGRAM DON'T HAVE AUTHORIZATION RULES")
            _check01 = test_authorization.check_authorization("tests/configtool_tests2.py", ["instance_id"], "R")
            assert not _check01, "Program check with no authorization failed!"
            print("## TEST PASSED ##")
            # TEST02
            print("CHECKING IF THE CALL USES INVALID OPERATION MODE")
            _check02 = test_authorization.check_authorization("tests/configtool_tests.py", ["instance_id"], "S")
            assert not _check02, "Failed to check if program has invalid operation!"
            print("## TEST PASSED ##")
            # TEST03
            print("CHECING IF THE CALL SUCCESSFUL WITH DIRECT CALL")
            _check03 = test_authorization.check_authorization("tests/configtool_tests.py", ["instance_id"], "R")
            assert _check03 is True, "Failed to check if program has successful direct call!"
            print("## TEST PASSED ##")
            # TEST04
            print("CHECKING WITH INDIRECT CALL")
            _check04 = test_authorization.check_authorization("tests/configtool_tests.py", ["test", "test_sample"], "R")
            assert _check04 is True, "Failed to check if program has indirect call!"
            print("## TEST PASSED ##")
            # TEST05
            print("CHECKING FAIL WITH INDIRECT CALL")
            _check05 = test_authorization.check_authorization("tests/configtool_tests.py", ["test", "test_sample"], "U")
            assert _check05 is False, "Failed to check if program has indirect call!"
            print("## TEST PASSED ##")
        except Exception as e:
            print(f"Error while checking test cases: {e}")
            self.fail("Test failed with exception!")


if __name__ == '__main__':
    unittest.main()
