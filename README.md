# MCM Export Tools

Tools used to export various MCM object types.

These tools interact with the MCM AdminService REST API.

## backup_mcm_applications.py
Query MCM for all applications; save the json data (including SDMPackageXML); save any .ps1, .bat, .cmd, .txt files referenced in the Install and Uninstall command line properties.