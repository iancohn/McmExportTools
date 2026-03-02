#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2026 Ian Cohn
# https://www.github.com/iancohn/mcm_export_tools
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
# This module was modeled heavily on AutoPkg (https://github.com/autopkg/autopkg)
# frameworks. 

import argparse
import atexit
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import getpass
from lxml import etree
import smbclient
from requests_gssapi import HTTPKerberosAuth, OPTIONAL
import dns.resolver

def is_empty(object: any) -> bool:
    if object is None:
        return True
    elif isinstance(object,bool):
        return ([False,True].__contains__(object) == False)
    elif isinstance(object,str):
        return (object == '')
    elif isinstance(object,dict):
        return (object == {})
    else:
        raise TypeError(f"Type ({type(object).__name__}) unhandled by is_empty")

__all__ = ["McmExporterBase"]

class McmExporterBase(dict):
    def output(self, msg, verbose_level=1) -> None:
        """Copied from https://github.com/autopkg/autopkg : Code/autopkglib/__init__.py
        Print a message if verbosity is >= verbose_level
        """
        _arg_verbose_level = self.args.verbose or 0
        if _arg_verbose_level >= verbose_level:
            print(f"{self.__class__.__name__}: {msg}", flush=True)
    @staticmethod
    def add_common_args(parser : argparse.ArgumentParser):
        """Seed common arguments into the module"""
        parser.add_argument("--mcm-user", required=True)
        parser.add_argument("--mcm-password", required=True)
        parser.add_argument("--mcmserver", required=True)
        parser.add_argument("--verify", required=False, default=False)
        parser.add_argument("--limit", type=int, required=False, default=0)
        _default_repo_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        parser.add_argument("--export-repo-path", type=str, default=_default_repo_path,dest='export_repo_path')
        parser.add_argument("--krb-config-type", type=str, choices=['auto','query','custom'], required=False, default='auto')
        parser.add_argument("--krb-config-path", type=str,required=False,default='')
        parser.add_argument("-v","--verbose",action="count",default=0)
        parser.add_argument("--keep-env",action='store_true')
    def strip_namespaces(self,element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element
    def convert_sdmpackagexml(
            self,
            sdmpackagexml : str,
            remove_namespaces : bool = True) -> etree.Element:
        """Convert an SDMPackageXML string to an etree.Element object."""
        xml_element = etree.XML(
            sdmpackagexml.replace(
                (
                    '<?xml version="1.0" encoding="'
                    'utf-16"?>'
                ),
                '',
                1
            ).replace(
                (
                    "<?xml version='1.0' "
                    "encoding='utf-16'?>"
                ),
                '',
                1
            )
        )
        if remove_namespaces:
            xml_element = self.strip_namespaces(
                xml_element
                )
        return xml_element
    @staticmethod
    def convert_unc_path(unc_path : str) -> str:
        """Convert a simple UNC path to a unix style smb path"""
        return unc_path.rstrip('\\').replace('\\','/')
    @staticmethod
    def load_json(json_path : str, default_output = {}):
        """Load a json file from a path"""
        _json_path = Path(json_path)
        if not (_json_path.is_file() and _json_path.exists()):
            return default_output
        with _json_path.open() as f:
            data = json.load(f)
        return data
    @staticmethod
    def write_json(data : dict, output_path : str, create_parent_dirs : bool = True):
        """Write the contents of a dictionary out to a file"""
        _path = Path(output_path)
        if create_parent_dirs:
            _path.parent.mkdir(parents=True,exist_ok=True)
        with _path.open("w") as f:
            json.dump(data, f, indent=2)
    @staticmethod
    def get_archived_content_files(root_path : str, depth : int=5) -> list:
        """Recurse a directory and return the absolute paths of any
        descendant files"""
        root = Path(root_path).resolve()
        files = []
        for p in root.rglob("*"):
            if p.is_file() and len(p.relative_to(root).parts) >= depth:
                files.append(str(p.absolute()))
        return files
    @staticmethod
    def remove_empty_directories(root_path):
        """Recurse a folder, delete any empty directories."""
        for root, dirs, files in os.walk(root_path, topdown=False):
            for d in dirs:
                dir_path = os.path.join(root, d)
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
    def try_copy_smb_file_to_local(
            self,
            smb_source_path : str,
            local_destination_path : str) -> bool:
        """Attempt to mount an smb path and copy the indicated file"""
        try:
            _ = os.makedirs(os.path.dirname(local_destination_path), exist_ok=True)
            self.output(f"Archived Content Folder ({os.path.dirname(local_destination_path)}) exists: {os.path.exists(os.path.dirname(local_destination_path))}", 3)
            smbclient.ClientConfig(username=self.args.mcm_user,password=self.password)
            src = smb_source_path.replace("/",r'\\')
            self.output(f"Source file smb path: {src}", 3)
            self.output(f"Local destination path: {local_destination_path}", 3)
            with smbclient.open_file(src,mode="rb") as remote, open(local_destination_path, mode="wb") as local:
                shutil.copyfileobj(remote,local)
            return True
        except Exception as e:
            self.output(e, 2)
            return False
    def initialize_headers(self):
        self.headers = {
            "Accept": "application/json", 
            "Content-Type": "application/json"
        }
    def initialize_ssl_verification(self):
        _ssl_verify = self.args.verify
        if isinstance(_ssl_verify, bool) or ['false','true'].__contains__(str(_ssl_verify).lower()):
            self.ssl_verify = str(_ssl_verify).lower == 'true'
        elif isinstance(_ssl_verify, str):
            if _ssl_verify.startswith('\\\\'):
                _ssl_verify = os.path.join(os.path.dirname(__file__),"ssl.pem")
                self.output(f"Copying remote cert .pem file to {_ssl_verify}", 4)
                ssl_copy_success = self.try_copy_smb_file_to_local(smb_source_path=self.args.verify,local_destination_path=_ssl_verify)
                self.output(f"SSL Copy succeeded: {ssl_copy_success}", 4)
            else:
                self.output("SSL path appears to be local")
            self.ssl_verify = str(Path(_ssl_verify).resolve())
        self.output(f"SSL Verify: {type(self.ssl_verify).__name__}({self.ssl_verify})", 4)
    def get_ssl_verify_param(self):
        """Get the value of the 'verify' parameter for http requests
        """
        if self.__getattribute__('ssl_verify') is not None and (
            isinstance(self.ssl_verify, bool) or isinstance(self.ssl_verify, str)
            ):
            return self.ssl_verify
        try:
            self.initialize_ssl_verification()
            return self.ssl_verify
        except Exception as e:
            raise LookupError(f"Failed to retrieve ssl verification: {e}")
    def _teardown_kerberos_env(self,ccname : str):

        if self._krb5_config_backup != '':
            self.output(f'Reverting KRB5_CONFIG', 2)
            self.output(f'KRB5_CONFIG: {self._krb5_config_backup}', 3)
            os.environ['KRB5_CONFIG'] = self._krb5_config_backup
        else:
            self.output('Unsetting KRB5_CONFIG environment variable', 3)
            krb5_config_unset = subprocess.run(['unset','KRB5_CONFIG'], shell=True, capture_output=True,text=True,check=True)
            self.output(f'KRB5_CONFIG unset return code: {krb5_config_unset.returncode}', 3)
        
        if self._krb5ccname_backup != '':
            self.output(f'Reverting KRB5CCNAME', 2)
            self.output(f'KRB5CCNAME: {self._krb5ccname_backup}', 3)
            os.environ['KRB5CCNAME'] = self._krb5ccname_backup
        else:
            self.output('Unsetting KRB5CCNAME environment variable', 3)
            krb5ccname_unset = subprocess.run(['unset','KRB5CCNAME'], shell=True, capture_output=True,text=True,check=True)
            self.output(f'KRB5CCNAME unset return code: {krb5ccname_unset.returncode}', 3)
        
        if True == self.args.keep_env:
            self.output('--keep-env was used')
            self.output(f'Temp KRB5_CONFIG: {self._krb5_config}')
            self.output(f'Temp KRB5CCNAME: {self._krb5ccache}')
            return

        self.output('--keep-env was not used. Destroying temporary files', 3)
        self.output(f"Calling kdestroy", 2)
        self.output(f"KRB5CCNAME: {ccname}", 3)
        teardown_result = subprocess.run(['kdestroy','-c',f'{ccname}'],capture_output=True,check=True,text=True)
        self.output(f"kdestroy return code: {teardown_result.returncode}", 2)
        
        if os.path.exists(self._krb5_config):
            self.output("Deleting temporary KRB5_CONFIG", 3)
            _ = os.unlink(self._krb5_config)

        if os.path.exists(self._krb5ccache):
            self.output('Deleting temporary credential cache', 3)
            _ = os.unlink(self._krb5ccache)
    def _build_krb_config(self,realm: str, domain: str, auto_resolve: bool, kdcs: list[str], admin_servers: list[str]) -> str:
        lines = []
        lines.append('[libdefaults]')
        lines.append(f'\tdefault_realm = {realm}')
        lines.append('\tforwardable = true')
        lines.append('\trdns = false')
        if auto_resolve:
            lines.append('\tdns_lookup_kdc = true')
            lines.append('\tdns_lookup_realm = true')
        lines.append('')
        if not auto_resolve:
            lines.append('[realms]')
            lines.append(f'\t{realm}' + ' = {')
            for kdc in kdcs:
                lines.append(f'\t\tkdc = {kdc}')
            if admin_servers:
                for host in admin_servers:
                    lines.append(f'\t\tadmin_server = {host}')
            elif kdcs:
                lines.append(f'\t\tadmin_server = {kdcs[0].split(":")[0]}')
            lines.append('\t}')
            lines.append('')
        lines.append('[domain_realm]')
        lines.append(f'\t.{domain.lower()} = {realm}')
        lines.append(f'\t{domain.lower()} = {realm}')
        lines.append('')
        return '\n'.join(lines)

    def _resolve_kpasswd_hosts(self,realm: str) -> list[str]:
        """SRV lookup for _kpasswd._tcp.<realm>."""
        try:
            answers = dns.resolver.resolve(f'_kpasswd._tcp.{realm.lower()}', 'SRV')
            sorted_records = sorted(answers, key=lambda r: (r.priority, r.weight))
            return [r.target.to_text().rstrip('.') for r in sorted_records]
        except dns.exception.DNSException:
            return []
    
    def _resolve_kdc_hosts(self,realm: str) -> list[str]:
        """SRV lookup for _kerberos._tcp.<realm>, returns list of 'host:port' sorted by priority."""
        try:
            answers = dns.resolver.resolve(f'_kerberos._tcp.{realm.lower()}', 'SRV')
            sorted_records = sorted(answers, key=lambda r: (r.priority, r.weight))
            return [f'{r.target.to_text().rstrip(".")}:{r.port}' for r in sorted_records]
        except dns.exception.DNSException:
            return []

    def _resolve_realm(self,domain: str) -> str:
        """Attempt DNS TXT lookup for _kerberos.<domain>, fall back to uppercased domain."""
        try:
            answers = dns.resolver.resolve(f'_kerberos.{domain}', 'TXT')
            for rdata in answers:
                for txt in rdata.strings:
                    return txt.decode()
        except Exception as e:
            pass
        return domain.upper()

    def _normalize_username(self,username : str, realm : str) -> str:
        """Normalize the realm in the provided user name."""
        if not username.__contains__('@') and not username.__contains__('\\'):
            self.output("Username contains neither @ nor \\. No logical place to infer a realm", 3)
            return username
        if len(username.split('@')) == 2:
            self.output("Username in user@domain format.", 3)
            user_name = username.split('@')[0].strip()
            user_domain = username.split('@')[-1].strip()
        elif len(username.split('\\')) == 2:
            self.output("Username in user@domain format.", 3)
            user_name = username.split('\\')[0].strip()
            user_domain = username.split('\\')[-1].strip()
        else:
            raise ValueError("Unhandled username format.")
        
        if user_domain.upper() != realm.upper():
            self.output(f"user_domain: {user_domain}\trealm: {realm}", 3)
            raise ValueError("User domain and Realm do not match.")
        
        normalized = f"{user_name}@{realm}"
        return normalized

    def _initialize_temp_kerberos_env(self):
        self.output("Initializing temporary kerberos environment", 2)
        
        pwd_file = tempfile.NamedTemporaryFile(mode='w',suffix='.pwd',delete=False)
        pwd_file.write(self.password)
        pwd_file.close()
        self.pwd_file = pwd_file.name
        atexit.register(os.unlink,pwd_file.name)

        ccache = tempfile.mkstemp(suffix='.ccache')
        ccname = f'FILE:{ccache[1]}'
        self._krb5ccache = ccache[1]

        self._krb5_config_backup = os.environ.get('KRB5_CONFIG','')
        self._krb5ccname_backup = os.environ.get('KRB5CCNAME', '')

        self.output("Generating kerberos config.", 3)
        server_fqdn = self.args.mcmserver
        krb_config_type = self.args.krb_config_type
        
        parts = server_fqdn.lower().split('.')
        domain = '.'.join(parts[1:]) if len(parts) > 2 else server_fqdn.lower()
        realm = self._resolve_realm(domain)

        krb_config_params = {
            'realm': realm,
            'domain': domain,
        }
        if krb_config_type == 'query':
            self.output('Realm information will be determined using dns queries')
            krb_config_params['auto_resolve'] = False
            krb_config_params['kdcs'] = self._resolve_kdc_hosts(realm)
            krb_config_params['admin_servers'] = self._resolve_kpasswd_hosts(realm)
        else:
            self.output('Realm information will be auto resolved', 3)
            krb_config_params['auto_resolve'] = True
            krb_config_params['kdcs'] = []
            krb_config_params['admin_servers'] = []
        
        if not krb_config_params['auto_resolve'] and not krb_config_params['kdcs']:
            raise RuntimeError(f"SRV lookup for _kerberos._tcp.{realm.lower()} returned no results and auto_resolve is False.")
        krb5_config = self._build_krb_config(**krb_config_params)
        self.output('Writing out KRB5 config', 3)
        conf = tempfile.NamedTemporaryFile(mode='w',suffix='.krb5.config',delete=False)
        conf.write(krb5_config)
        conf.close()
        self.output("Setting os environment variables", 3)
        self._krb5_config = conf.name
        os.environ['KRB5CCNAME'] = ccname
        os.environ['KRB5_CONFIG'] = self._krb5_config
        
        atexit.register(self._teardown_kerberos_env,ccname)

        self.output(f'KRB5_CONFIG: {self._krb5_config}', 3)
        self.mcm_user = self._normalize_username(username=self.mcm_user, realm=realm)
        self.output(f'Username: {self.mcm_user}', 3)
        self.output(f'Calling kinit', 2)
        kinit_result = subprocess.run(['kinit',f'--password-file={self.pwd_file}', '-c',ccname, self.mcm_user], capture_output=True,text=True,check=True)
        self.output(f'kinit return code: [{kinit_result.returncode}] {kinit_result.stderr}')
        
    def initialize_auth(self):
        #self.initialize_ntlm_auth()
        self.initialize_gss_auth()
    def get_mcm_auth(self):
        #self.get_mcm_ntlm_auth()
        return self.get_mcm_gss_auth()
    def initialize_gss_auth(self):
        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcmserver cannot be blank")
        self.auth = None
        _ = self.get_mcm_gss_auth()
    def get_mcm_gss_auth(self):
        """Construct a HTTPKerberosAuth auth object from the retrieved
        details
        """
        
        if self.__getattribute__('auth') is not None and \
            isinstance(self.auth, HTTPKerberosAuth):
            return self.auth
        self.output("GSSAPI Auth object does not currently exist. It will be created", 2)
        try:
            self.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
            return self.auth
        except Exception as e:
            raise LookupError(f"Failed to retrieve credentials: {e}")
    def cleanup_gssapi(self):
        if hasattr(self, 'auth'):
            del self.auth
        import gc
        gc.collect()
    def cleanup(self):
        self.cleanup_gssapi
    def __init__(self, args):
        self.exportable_files = []
        self.exportable_files_by_srcdst_hash = {}
        self.source_files_by_sourcepathhash = {}
        self.unused_archived_content_files = []
        self.smb_mounts_by_server_share = {}
        self.smb_mount_infos = []
        self.args = args
        self.fqdn = args.mcmserver
        self.mcm_user = self.args.mcm_user
        if args.mcm_password == '*':
            self.password = getpass.getpass("Password: ")
        else:
            self.password = args.mcm_password.strip('"\'')
        if args.krb_config_type == 'custom':
            raise ValueError("Custom kerberos config files not yet supported.")
        self.initialize_headers()
        self.initialize_ssl_verification()
        self.initialize_auth()
        self._initialize_temp_kerberos_env()
        self.output("McmExporterObject initialized", 3)
        
if __name__ == "__main__":
    PROCESSOR = McmExporterBase()
    PROCESSOR.execute_shell()
