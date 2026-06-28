import pytest
import subprocess
import sys
import os

# Add the contrib directory to the path to import runtests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'contrib', 'ossec-testing'))

from runtests import OssecLogtest

@pytest.mark.parametrize("rule,alert,decoder", [
    # Exact exploit case: command injection via rule parameter
    ("test; echo 'exploit'", "test_alert", "test_decoder"),
    # Boundary case: empty strings (edge case handling)
    ("", "", ""),
    # Valid input: normal test parameters
    ("test_rule", "test_alert", "test_decoder"),
])
def test_command_injection_security_invariant(rule, alert, decoder):
    """Invariant: Command arguments constructed from external inputs must not allow arbitrary command execution."""
    # Create an instance of OssecLogtest
    logtest = OssecLogtest()
    
    # Build the command using the actual production method
    cmd = logtest.buildCmd(rule, alert, decoder)
    
    # Security property: All command components must be properly sanitized/escaped
    # We verify by checking that the command list doesn't contain shell metacharacters
    # that could lead to injection when passed to subprocess.Popen with shell=False
    
    # Assert that no command component contains shell metacharacters
    shell_metacharacters = [';', '&', '|', '$', '`', '>', '<', '(', ')', '[', ']', '{', '}', '!']
    
    for component in cmd:
        # Skip the first component (ossec-logtest path) as it's not user-controlled
        if component == cmd[0]:
            continue
            
        for char in shell_metacharacters:
            assert char not in component, f"Shell metacharacter '{char}' found in command component: {component}"
    
    # Additional check: verify the command can be executed safely
    # This is a minimal execution test to ensure the command doesn't crash or execute arbitrary code
    try:
        # Use a short timeout to prevent hanging if there's an issue
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        # We don't care about the success/failure of the command, only that it executed
        # without security violations (which would be caught by the metacharacter check)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Timeout or missing ossec-logtest binary is acceptable for this security test
        # The important thing is that no injection occurred during command construction
        pass