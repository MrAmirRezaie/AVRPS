import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import AVRPS as avrps


def test_configuration_manager_present() -> None:
    assert hasattr(avrps, 'ConfigurationManager')


def test_avrps_main_class() -> None:
    assert hasattr(avrps, 'AdvancedVulnerabilityPatcher')
