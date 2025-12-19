import importlib
import pytest

import AVRPS as avrps


def test_module_version_and_constants():
    assert hasattr(avrps, 'VERSION')
    assert avrps.VERSION == '3.0.0'
    assert hasattr(avrps, 'DEFAULT_CONFIG_FILE')


def test_severity_from_string():
    lvl = avrps.SeverityLevel.fromString('high')
    assert lvl == avrps.SeverityLevel.HIGH
    lvl_unknown = avrps.SeverityLevel.fromString('not-a-level')
    assert lvl_unknown == avrps.SeverityLevel.UNKNOWN


def test_operating_system_detect():
    os_detected = avrps.OperatingSystem.detect()
    assert isinstance(os_detected, avrps.OperatingSystem)


def test_systempackage_to_from_dict_roundtrip():
    sp = avrps.SystemPackage(
        name='example',
        version='1.2.3',
        architecture=avrps.Architecture.X64,
        vendor='ACME'
    )
    d = sp.toDict()
    sp2 = avrps.SystemPackage.fromDict(d)
    assert sp2.name == sp.name
    assert sp2.version == sp.version
    assert sp2.architecture == sp.architecture
