#!/usr/bin/python
# OSSEC Rules list
# Simple script to get a short brief of every rule in OSSEC rules folder
# pedro@wazuh.com

import sys
import re
import os

rules_directory = "/var/ossec/rules/"

def GetRulesList(fulldir, filename):
    rule_detected = 0
    rule_description = 0
    level = ""
    sidid = ""
    description = ""
    pattern_idlevel = re.compile(r'<rule id="(.+?)".+level="(.+?)"')
    pattern_description = re.compile(r'<description>(.+?)</description>')
    pattern_endrule = re.compile(r'</rule>')
    try:
        with open(fulldir) as f:
            lines = f.readlines()
            for line in lines:
                if rule_detected == 0:
                    match = re.findall(pattern_idlevel, line)
                    if match:
                        rule_detected = 1
                        sidid = match[0][0]
                        level = match[0][1]
                else:
                    if rule_description == 0:
                        match = re.findall(pattern_description, line)
                        if match:
                            rule_description = 1
                            description = match[0]
                    if rule_description == 1:
                        match = re.findall(pattern_endrule, line)
                        if match:
                            print "%s - Rule %s - Level %s -> %s" % (filename,sidid,level,description)
                            rule_detected = 0
                            rule_description = 0
                            level = ""
                            sidid = ""
                            description = ""
    except EnvironmentError: 
           print ("Error: OSSEC rules directory does not appear to exist")
           
if __name__ == "__main__":
    print ("Reading rules from directory %s") % (rules_directory)
    for root, directories, filenames in os.walk(rules_directory):
        for filename in filenames:
            if filename[-4:] == ".xml":
                GetRulesList(os.path.join(root,filename), filename)
