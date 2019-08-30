#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unprotect Malware - Json Report file - json_report.py version 1.0

This module is the main file for generating the JSON report. This file will call every module of the project for the analysis.

"""
import re
#import sys
#import lief
import pefile
import datetime

#import json as JSON
import module.config
#from module.antiav import get_av_evasion
#from module.antiav import get_av_strings
#from module.antiav import get_pesize
from module.antivm import antivm_inst
from module.antivm import get_vm
#from module.disas import check_iat
#from module.disas import fake_jump
#from module.disas import flow_redirect
#from module.disas import garbage_byte
#from module.disas import nop_seq
#from module.network_evasion import get_url, get_ip
from module.packer import get_peid
from module.packer import possible_packing
from module.pe_info import check_tls
#from module.pe_info import display_resources
from module.pe_info import get_antidebug
#from module.pe_info import get_hash
#from module.pe_info import get_impfuzzy
#from module.pe_info import get_info
#from module.pe_info import get_mmh
#from module.pe_info import get_procinj
#from module.pe_info import get_richhash
from module.pe_info import get_sec
from module.strings import get_strings
from module.utils import yarascan

from fame.core.module import ProcessingModule


#report_json = {}

class unprotect(ProcessingModule):
    # You have to give your module a name, and this name should be unique.
    name = "Unprotect"
    # (optional) Describe what your module will do. This will be displayed to users.
    description = "Detect evasion techniques in samples"
    acts_on = ["executable"]


    # This method will be called, with the object to analyze in target
    def each(self, target):
        self.results = {}

        print(type(target))

        try:
            exefile = target
            exe = pefile.PE(exefile)
        except IndexError:
            print "[!] File error"

        strings_list = get_strings(exefile)

        # Exploit mitigating
        aslr_check, dep_check, seh_check, cfg_check = get_sec(exe)

        peid_detect = get_peid(exe)

        if not peid_detect:
            peid_detect = False

        pepack, emptysec, enaddr, vbsecaddr, ensecaddr, entaddr = possible_packing(exe)
        if bool(pepack):
            entropysec = "Sections entropy is high, the binary is possibly packed!"
        else:
            entropysec = False
        if bool(emptysec):
            emptysection = "Non-ascii or empty section names detected"
        else:
            emptysection = False
        if enaddr > entaddr:
            entryout = "Entry point is outside the .code section, the binary is possibly packed!"
        else:
            entryout = False

        sectiontab = []

        for section in exe.sections:
            section_row = {"NAME": section.Name.strip(), "VIRTUAL_ADDRESS": "0x" + str(section.VirtualAddress),
                           "SIZE": "0x" + str(section.Misc_VirtualSize), "ENTROPY": str(section.get_entropy())}
            sectiontab.append(section_row)

        if not sectiontab:
            sectiontab = False

        matches = yarascan(exefile, module.config.rule_packer)
        if not matches:
            matches = False

        # Anti-Sandboxing
        trk = get_vm(exefile)
        count = antivm_inst(exe)

        matches = yarascan(exefile, module.config.rule_antisb)
        if not matches:
            matches = False

        if not trk:
            trk = False

        if not count:
            count = False

        # Anti-Debugging
        tlscallback = check_tls(exe)
        if tlscallback:
            tls = "0x" + str(tlscallback)
        else:
            tls = False

        dbgmatches = get_antidebug(exe, module.config.antidbg_api)
        matchesdb = yarascan(exefile, module.config.rule_antidbg)
        if not matchesdb:
            matchesdb = False

        dbgtable = []

        for x, y in dbgmatches:
            dbgraw = {"ADDR": x, "API_NAME": y}
            dbgtable.append(dbgraw)

        if not dbgtable:
            dbgtable = False


        self.results = {
            'ASLR': aslr_check,
            'DEP': dep_check,
            'SEH': seh_check,
            'CFG': cfg_check},
        }

        print self.results

        return True
