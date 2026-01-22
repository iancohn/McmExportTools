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


import platform
import shutil
import json
import subprocess
import argparse
import getpass
from ctypes import c_int32
from datetime import datetime
from enum import Enum, auto
from os import path, walk
from io import BytesIO
from lxml import etree
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote
import smbclient

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
#if vendor_path not in sys.path:
#    sys.path.insert(0, vendor_path)

from requests_ntlm import HttpNtlmAuth

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
        parser.add_argument("-v","--verbose",action="count",default=0)
    def strip_namespaces(self,element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element
    def convert_sdmpackagexml(self,sdmpackagexml : str, remove_namespaces : bool = True) -> etree.Element:
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
    def smb_mounts_in_use(self) -> str:
        import subprocess
        p1 = subprocess.Popen(["lsof"], stdout=subprocess.PIPE, text=True)
        p2 = subprocess.run(["grep", "mds"], stdin=p1.stdout, capture_output=True, text=True)
        return f"[{p2.returncode}]\n{p2.stderr}\n{p2.stdout}"
    def try_copy_smb_file_to_local(self, smb_source_path : str,local_destination_path : str) -> bool:
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
        self.output(f"SSL Verify (pre-set): {type(_ssl_verify).__name__}({_ssl_verify})", 4)
        if isinstance(_ssl_verify, bool) or ['false','true'].__contains__(str(_ssl_verify).lower()):
            self.ssl_verify = str(_ssl_verify).lower == 'true'
        elif isinstance(_ssl_verify, str):
            if _ssl_verify.startswith('\\\\'):
                _ssl_verify = os.path.join(os.path.dirname(__file__),"ssl.pem")
                self.output(f"Copying remote cert .pem file to {_ssl_verify}")
                self.try_copy_smb_file_to_local(smb_source_path=_ssl_verify,local_destination_path=_ssl_verify)

            self.ssl_verify = str(Path(_ssl_verify).resolve())
        self.output(f"SSL Verify (post-set): {type(self.ssl_verify).__name__}({self.ssl_verify})", 4)
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
    def initialize_ntlm_auth(self):
        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcmserver cannot be blank")
        self.ntlm_auth = None
        _ = self.get_mcm_ntlm_auth()
    def get_mcm_ntlm_auth(self) -> HttpNtlmAuth:
        """Construct an HttpNtlmAuth object from the retrieved
        details
        """
        if self.__getattribute__('ntlm_auth') is not None and isinstance(self.ntlm_auth, HttpNtlmAuth):
            return self.ntlm_auth
        self.output("NTLM Auth object does not currently exist. It will be created", 2)
        try:
            if self.password is None:
                raise LookupError(f"No password found for {self.args.mcm_user}")
            self.ntlm_auth = HttpNtlmAuth(self.args.mcm_user, self.password)
            return self.ntlm_auth
        except Exception as e:
            raise LookupError(f"Failed to retrieve credentials: {e}")
    def __init__(self, args):
        self.exportable_files = []
        self.exportable_files_by_srcdst_hash = {}
        self.source_files_by_sourcepathhash = {}
        self.unused_archived_content_files = []
        self.smb_mounts_by_server_share = {}
        self.smb_mount_infos = []
        self.args = args
        self.ssl_verify = args.verify
        self.fqdn = args.mcmserver
        if args.passw == '*':
            self.password = getpass.getpass("Password: ")
        else:
            self.password = args.passw.strip('"\'')
        self.initialize_headers()
        self.initialize_ssl_verification()
        self.initialize_ntlm_auth()
        self.output("McmExporterObject initialized", 3)
        
if __name__ == "__main__":
    PROCESSOR = McmExporterBase()
    PROCESSOR.execute_shell()
