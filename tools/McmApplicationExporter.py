#!/usr/bin/python3
# pylint: disable=invalid-name
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

#import platform
import requests
import argparse
import json
from uuid import uuid4
from pathlib import Path
import shlex
import shutil

import os.path

from McmExportLib.McmExporterBase import ( #noqa: E402
    McmExporterBase,
)

__all__ = ["backup_mcm_applications"]

class McmApplicationExporter(McmExporterBase):
    def __init__(self, args):
        super().__init__(args)
    def get_all_mcm_applications(self,limit:int = 0) -> list:
        """Retrieve all SMS_ApplicationLatest objects from MCM"""
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_ApplicationLatest"
        self.output(f"Querying url: {url}",3)
        if (limit >= 1):
            body = {"$top": limit,}
        else:
            body = {}
        self.output(f"ssl_verify = {self.get_ssl_verify_param()}", 4)
        appSearchResponse = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_ntlm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
            params = body,
            timeout = (5,15)
        )
        self.output(f"Initial query finished. Status Code: {appSearchResponse.status_code}", 4)
        searchValue = appSearchResponse.json().get("value",[])
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}", 2)
        if searchValue.__len__() == 0:
            self.output(f"No applications found in {self.fqdn}", 2)
            return []
        self.output(f"Getting {len(searchValue)} application details", 2)
        all_application_details = []
        
        for v in searchValue:
            self.output(f"Getting application {v.get('CI_ID')}", 3)
            appUrl = f"https://{self.fqdn}/AdminService/wmi/SMS_Application({v.get('CI_ID')})"
            app = requests.request(
                method = 'GET', 
                url = appUrl, 
                auth = self.get_mcm_ntlm_auth(), 
                headers = self.headers, 
                verify = self.get_ssl_verify_param(),
            )
            app_value = app.json().get('value',[])
            if len(app_value) == 1:
                v['SDMPackageXML'] = app_value[0].get('SDMPackageXML','')
            all_application_details.append(v)
                
        return all_application_details
    @staticmethod
    def get_exportable_files_from_command(
        input_string : str,
        valid_extensions : list=['ps1','txt','bat','cmd']) -> list:
        """Inspect the command line string and return any arguments which look
        like file names with a valid extension
        """
        lower_exts = [v.lower() for v in valid_extensions.__iter__()]
        split_command = shlex.split(s=input_string, posix=False)
        files = []
        for command_part in split_command:
            stripped_part = command_part.strip('"\'')
            if stripped_part.startswith('.\\'):
                stripped_part = stripped_part[2:]
            if stripped_part.startswith("\\\\") or stripped_part.__contains__('://'):
                continue
            if lower_exts.__contains__(
                os.path.splitext(stripped_part)[1].lower().lstrip('.')
                ):
                files.append(stripped_part.replace('\\','/'))
        return files
    
    def new_exportable_file_info(
        self,
        root_path : str,
        file_relative_path : str,
        files_export_path : str):
        """Catalog unique files to be archived"""
        normalized_root_path = self.convert_unc_path(root_path)
        source_path = os.path.join(normalized_root_path,file_relative_path)
        destination_path = os.path.join(files_export_path,file_relative_path)
        src_path_hash = str(hash(source_path))
        dst_path_hash = str(hash(destination_path))
        srcdst_hash = "_".join([src_path_hash,dst_path_hash])

        if (self.exportable_files_by_srcdst_hash.__contains__(srcdst_hash)):
            self.output(f"{file_relative_path} has already been marked for export", 4)
            return
        self.output(f"Marking {file_relative_path} for export to folder {Path(files_export_path).parts[-2]}", 3)
        exportable_file_info = {
            "source_path": source_path,
            "destination_path": destination_path,
            "file_relative_path": file_relative_path,
        }
        self.exportable_files.append(exportable_file_info)
        self.exportable_files_by_srcdst_hash[srcdst_hash] = exportable_file_info
        if self.source_files_by_sourcepathhash.__contains__(src_path_hash) == False:
            self.source_files_by_sourcepathhash[src_path_hash] = {
                "file_path": source_path
            }
        if self.unused_archived_content_files.__contains__(destination_path):
            self.unused_archived_content_files.remove(destination_path)
        return
    
    def inspect_deployment_type_for_exportable_files(self,deployment_type) -> list:
        """Inspect a deployment type for exportable files. Catalog
        all files in instance
        """
        installer_nodes = deployment_type.xpath('Installer')
        self.output(f"{len(installer_nodes)} installer nodes", 4)
        if len(installer_nodes) != 1:
            return
        dt_logical_names = deployment_type.xpath('@LogicalName')
        if len(dt_logical_names) != 1:
            return
        dt_logical_name = dt_logical_names[0]
        _files_export_path = os.path.join(self.files_export_path, dt_logical_name)
        # Install
        install_content_ids = installer_nodes[0].xpath('CustomData/InstallContent/@ContentId')
        install_content_location = ""
        
        
        if len(install_content_ids) == 1:
            install_content_id = install_content_ids[0]
            installer_content_xpath = f"Contents/Content[@ContentId=\"{install_content_id}\"]/Location/text()"
            install_content_location = installer_nodes[0].xpath(installer_content_xpath)[0]
            install_commands = installer_nodes[0].xpath('CustomData/InstallCommandLine/text()')
            if len(install_commands) == 1:
                install_command = install_commands[0]
                self.output(f"Install Command: {install_command}", 4)
                installer_exportable_files = self.get_exportable_files_from_command(input_string=install_command)
                for ief in installer_exportable_files:
                    _ = self.new_exportable_file_info(root_path=install_content_location,file_relative_path=ief,files_export_path=os.path.join(_files_export_path,'Install'))
            
        # Uninstall
        uninstall_settings = installer_nodes[0].xpath('CustomData/UninstallSetting/text()')
        if uninstall_settings is None or len(uninstall_settings) != 1  or uninstall_settings[0] == 'NoneRequired':
            self.output("No uninstall content to examine.", 3)
            return
        uninstall_setting = uninstall_settings[0]
        if uninstall_setting == 'SameAsInstall':
            uninstall_content_location = install_content_location
        else:
            uninstall_content_ids = installer_nodes[0].xpath('CustomData/InstallContent/@ContentId')
            if len(uninstall_content_ids) == 1:
                uninstall_content_id = install_content_ids[0]
                uninstaller_content_xpath = f"Contents/Content[@ContentId=\"{uninstall_content_id}\"]/Location/text()"
                uninstall_content_location = installer_nodes[0].xpath(uninstaller_content_xpath)[0]
        self.output(f"Content Location: {uninstall_content_location}", 4)
        uninstall_commands = installer_nodes[0].xpath('CustomData/UninstallCommandLine/text()')
        if len(uninstall_commands) == 1:
            uninstall_command = uninstall_commands[0]
            self.output(f"Uninstall Command: {uninstall_command}", 4)
            uninstaller_exportable_files = self.get_exportable_files_from_command(input_string=uninstall_command)
            self.output(f"{', '.join(uninstaller_exportable_files)}", 4)
            for uef in uninstaller_exportable_files:
                _ = self.new_exportable_file_info(root_path=uninstall_content_location,file_relative_path=uef,files_export_path=os.path.join(_files_export_path,'Uninstall'))
    
    def execute_shell(self):
        try:
            self.output("Getting applications from mcm", 3)
            apps = self.get_all_mcm_applications(limit = self.args.limit)
            self.output(f"Got {len(apps)} applications from MCM.", 3)
            local_repo = os.path.join(self.args.export_repo_path,'Application')
            archived_app_short_models = [d for d in os.listdir(local_repo) if os.path.isdir(os.path.join(local_repo,d))]
            self.unused_archived_content_files.extend(self.get_archived_content_files(local_repo,depth=4))
            self.output(f"All archived content files in {local_repo}\n{json.dumps(self.unused_archived_content_files, indent=2)}", 4)
            self.output(", ".join([a['ModelName'].split('/')[1] for a in apps]), 4)
            current_app_short_models = []
            for app in apps:
                short_model = app.get('ModelName','ERR').split('/')[-1]
                current_app_short_models.append(short_model)
                base_export_path = os.path.join(local_repo,short_model)
                app_definition_path = os.path.join(base_export_path,'application.json')
                self.files_export_path = os.path.join(base_export_path,'archived_content')
                latest_app_revision = app.get('CIVersion',0)
                archived_app = self.load_json(app_definition_path)
                
                self.output(f"Application '{app.get('LocalizedDisplayName')}' revision \
                 {latest_app_revision} will be archived to {app_definition_path}.")
                self.write_json(data=app,output_path=app_definition_path)

                sdmpackagexml = app.get('SDMPackageXML','')
                if sdmpackagexml == '':
                    continue
                
                xml_element = self.convert_sdmpackagexml(sdmpackagexml=sdmpackagexml)
                deployment_types = xml_element.xpath('/AppMgmtDigest/DeploymentType')    
                self.output(f"{app.get('ModelName')} has {len(deployment_types)} deployment types",3)
                
                for d in deployment_types:
                    self.inspect_deployment_type_for_exportable_files(deployment_type=d)
                
                if (archived_app.get('CIVersion',0) == latest_app_revision):
                    self.output(f"Application '{app.get('LocalizedDisplayName')}' \
                        revision {latest_app_revision} is already archived. Skipping.")
                    continue
                
            self.output("Copying files to archive", 1)
            for f in self.exportable_files:
                copy_result = self.try_copy_smb_file_to_local(
                    smb_source_path = f['source_path'],

                    local_destination_path = f['destination_path'])
                self.output(f"Copy succeeded: {copy_result}",2)

            if self.args.remove_deleted == False:
                self.output("Declining to remove deleted application archives.", 2)
                return

            self.output("Removing archived content files no longer needed by MCM.", 1)
            self.output(f"{json.dumps(self.unused_archived_content_files,indent=2)}")
            for cf in self.unused_archived_content_files:
                self.output(f"Removing '{cf}", 3)
                _cf = Path(cf)
                _cf.unlink(missing_ok=True)
            self.output(f"Removing any empty directories from the archive.", 2)
            self.remove_empty_directories(local_repo)
            self.output("Removing deleted applications from archives.",1)
            for a in archived_app_short_models:
                if current_app_short_models.__contains__(a) == False:
                    self.output(f"{a} does not exist in MCM site. It will be deleted.", 2)
                    delete_path = os.path.join(local_repo,a)
                    shutil.rmtree(delete_path,ignore_errors=True)
            
        except Exception as e:
            raise ValueError(e)
        finally:
            pass

if __name__ == "__main__":
    # Add script specific arguments; parse
    parser = argparse.ArgumentParser()
    McmExporterBase.add_common_args(parser)
    parser.add_argument("--remove-deleted", action="store_true")
    args = parser.parse_args()

    PROCESSOR = McmApplicationExporter(args)
    PROCESSOR.execute_shell()
