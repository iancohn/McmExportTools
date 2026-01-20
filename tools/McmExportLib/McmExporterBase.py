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
import uuid
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
        parser.add_argument("--user", required=True)
        parser.add_argument("--passw", required=True)
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
    def prepare_mount_parent(self,local_path=f"/tmp/{uuid.uuid4().__str__()}") -> str:
        """Create a temporary mount folder"""
        parent_path = Path(local_path)
        if parent_path.exists():
            raise FileExistsError(f"Parent mount path {parent_path.absolute()} already exists.")
        else:
            parent_path.mkdir()
        return parent_path.absolute().__str__()
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
    def mount_smb(
            self,local_path : str,smb_path, smb_user : str, smb_password : str,
            fs_mounter : str='/sbin/mount_smbfs',
            raise_error_on_failure : bool = True,
            ) -> dict:
        result = {"success": False}
        try:
            _smb_path = smb_path.replace('\\','/')
            server_name = _smb_path.strip('/').split('/')[0].lower()
            result['server_name'] = server_name
            share_name = _smb_path.strip('/').split('/')[1].lower()
            result['share_name'] = share_name
            hashable_key_name = f"{server_name}_{share_name}"
            self.output(f"Share key name: {hashable_key_name}", 2)
            if self.smb_mounts_by_server_share.__contains__(hashable_key_name):
                self.output(f"Mount {hashable_key_name} exists", 2)
                self.output((json.dumps(self.smb_mounts_by_server_share[hashable_key_name],indent=2)),3)
                return self.smb_mounts_by_server_share[hashable_key_name]
            self.output(f"{hashable_key_name} will be mounted", 2)
            server_name_short = server_name.split('.')[0]
            result['server_name_short'] = server_name_short
            mount_path = Path(f"{local_path}/{share_name}")
            result['mount_path'] = str(mount_path.absolute())
            if mount_path.exists():
                raise FileExistsError(f"Parent mount path {str(mount_path.absolute())} already exists.")
            else:
                mount_path.mkdir(parents=True,exist_ok=True)
            
            split_smb_user = smb_user.split('@')
            if len(split_smb_user) > 1:
                user_string = f"{split_smb_user[1]};{split_smb_user[0]}"
            else:
                user_string = smb_user
            enc_password = quote(smb_password, safe='')
            smb_path = f"//{user_string}:{enc_password}@{server_name}/{share_name}"
            share_path = f"\\\\{server_name}\\{share_name}"
            result['share_path'] = share_path
            #opts = "nobrowse,soft,vers=3.0,ro,noperm"
            mount_result = subprocess.run(
                args = [
                    fs_mounter,
                    "-v",
                    #"-o", opts,
                    smb_path,
                    str(mount_path.absolute())
                ],
                check=False,
                capture_output=True,
                text=True
            )
            self.output(mount_result.stdout, 3)
            self.output(mount_result.stderr,3)
            ls_result = subprocess.run(
                args = [
                    "ls",
                    "-l",
                    "-R",
                    mount_path.absolute()
                ],
                check=False,
                capture_output=True,
                text=True
            )
            self.output(ls_result.stdout, 3)
            self.output(ls_result.stderr, 3)
            result['success'] = True
            self.smb_mount_infos.append(result)
            self.smb_mounts_by_server_share[hashable_key_name] = result
            return result
        except Exception as e:
            if raise_error_on_failure:
                self.output(e, 3)
                raise e
    def dismount_smb(
            self,mount_info : dict, 
            fs_dismounter : str='/sbin/umount') -> bool:
        """Dismount a mounted smb share given its mount_info"""
        if mount_info.get('success', False) == False:
            return True
        try:
            self.output(f"Dismounting {mount_info.get('mount_path')}", 2)
            _ = subprocess.run(args = [fs_dismounter,mount_info.get('mount_path')],check=True,capture_output=True,text=True)
            self.remove_empty_directories(root_path=os.path.dirname(mount_info['mount_path']))
            _ = subprocess.run(
                args = [
                    "rmdir", 
                    mount_info['mount_path'],
                ],
                check=True,capture_output=True,text=True)
            return True
        except Exception as e:
            return False
    def try_copy_smb_file_to_local(self, file_relative_path:str, smb_source_path : str,local_destination_path : str) -> bool:
        """Attempt to mount an smb path and copy the indicated file"""
        try:
            self.output(f"Source file smb path: {smb_source_path}", 3)
            self.output(f"File relative path: {file_relative_path}", 3)
            self.output(f"Mounting share (if needed)", 2)
            mount = self.mount_smb(
                local_path=self.parent,smb_path=smb_source_path.lower(),
                smb_user=self.args.user,smb_password=self.password,
                raise_error_on_failure=True)
            share_path = f"//{mount['server_name'].lower()}/{mount['share_name'].lower()}"
            self.output(f"Share path: {share_path}", 3)
            self.output(json.dumps(mount,indent=2), 4)
            share_mount_path = mount['mount_path'].lower().rstrip('/')
            local_src_path = smb_source_path.lower().replace(share_path,share_mount_path)
            self.output(f"Mount succeeded: {mount['success']}", 2)
            self.output(f"Local source file path: {local_src_path}", 3)
            self.output(f"Local destination path: {local_destination_path}", 3)
            os.makedirs(os.path.dirname(local_destination_path), exist_ok=True)
            if mount['success'] == False:
                self.output(json.dumps(mount,indent=2), 3)
                raise ConnectionAbortedError("Could not connect to smb path.")
            shutil.copy2(local_src_path,local_destination_path)
            if self.unused_archived_content_files.__contains__(local_destination_path):
                self.unused_archived_content_files.remove(local_destination_path)
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
        if isinstance(_ssl_verify, bool) or ['False','True'].__contains__(str(_ssl_verify)):
            self.ssl_verify = bool(_ssl_verify) 
        elif isinstance(_ssl_verify, str):
            if _ssl_verify.startswith('\\\\'):
                _ssl_verify = self.convert_unc_path(_ssl_verify.lower())
                mount = self.mount_smb(local_path=self.parent,smb_path=_ssl_verify,smb_user=self.args.user,smb_password=self.password,raise_error_on_failure=True)
                _ssl_verify = _ssl_verify.replace(f"//{mount['server_name']}/{mount['share_name']}", mount['mount_path'])

            self.ssl_verify = str(Path(_ssl_verify).resolve())
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
                raise LookupError(f"No password found for {self.args.user}")
            self.ntlm_auth = HttpNtlmAuth(self.args.user, self.password)
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
        self.parent = self.prepare_mount_parent()
        self.initialize_headers()
        self.initialize_ssl_verification()
        self.initialize_ntlm_auth()
        
if __name__ == "__main__":
    PROCESSOR = McmExporterBase()
    PROCESSOR.execute_shell()
