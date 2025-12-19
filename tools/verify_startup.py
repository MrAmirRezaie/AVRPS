"""
Quick startup verification script for AVRPS.
Run from repository root inside the virtualenv.
"""
import sys
import os
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import AVRPS
    from AVRPS import ConfigurationManager, DatabaseManager, LocalCveDatabase

    print("Imported AVRPS module successfully")

    cfg = ConfigurationManager()
    print("ConfigurationManager initialized")

    db = DatabaseManager(':memory:')
    print("DatabaseManager initialized (in-memory)")

    cvedb = LocalCveDatabase('test_cve.json')
    print(f"LocalCveDatabase initialized with {len(cvedb.vulnerabilities)} CVEs")

    print("STARTUP VERIFICATION: OK")
    sys.exit(0)

except Exception as e:
    print("STARTUP VERIFICATION: FAILED")
    print(e)
    traceback.print_exc()
    sys.exit(2)
