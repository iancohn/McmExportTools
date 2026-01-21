# MCM Export Tools

Tools used to export various MCM object types.

These tools interact with the MCM AdminService REST API.

# Installation

To connect to an MCM instance, you will need to create an MCM credential.

## macOS

'com.github.iancohn.mcm_export_tools' is not required for the -s parameter, however if specifying something custom, you'll need to note it and use it to populate the 'keychain_password_service' input variable in the processor(s) you are using manually.

```zsh

username="username@domain.com"

security add-generic-password -a $username -s com.github.iancohn.mcm_export_tools -T '/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3' -U -w

```


## backup_mcm_applications.py

Query MCM for all applications; save the json data (including SDMPackageXML); save any .ps1, .bat, .cmd, .txt files referenced in the Install and Uninstall command line properties.
