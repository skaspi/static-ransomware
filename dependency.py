#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Mon Dec 11 15:12:16 2017

@authors Rafael,Dmitriy
Ransomware Detection Project
Technion, Haifa, Israel

The purpose of this script is to detect
suspicious API calls during the static analysis.
"""
import sys


def main():
    crypt, vm, proc_rep, pr_esc, debug = 0, 0, 0, 0, 0
    flag = 0

    file = open(sys.argv[1], 'r')
    s = file.read()

    # Anti Debugging check
    if s.find('IsDebuggerPresent') != -1:
        debug = 1

    # Anti VM check
    if s.find('GetCursorPos') != -1:
        vm += 1
    if s.find('GetUserName') != -1:
        vm += 1
    if s.find('GetModuleFileName') != -1:
        vm += 1
    if s.find('GetLogicalDriveStrings') != -1:
        vm += 1
    if s.find('GetDriveType') != -1:
        vm += 1
    if s.find('DeviceIoControl') != -1:
        vm += 1
    if s.find('GetSystemInfo') != -1:
        vm += 1
    if s.find('GlobalMemoryStatusEx') != -1:
        vm += 1
    if s.find('GetModuleHandleA') != -1:
        vm += 1
    if s.find('GetAdaptersAddresses') != -1:
        vm += 1

    # Process Replacement check
    if s.find('CreateFileMapping') != -1:
        proc_rep += 1
    if s.find('MapViewOfFile') != -1:
        proc_rep += 1
    if s.find('WriteProcessMemory') != -1:
        proc_rep += 1
    if s.find('VirtualAllocEx') != -1:
        proc_rep += 1

    # Privilege Escalation check
    if s.find('AdjustTokenPrivileges') != -1:
        pr_esc += 1
    if s.find('OpenProcessToken') != -1:
        pr_esc += 1

    # Crypto-libraries presence check
    if s.find('NCRYPT.DLL') != -1:
        crypt = 1
    if s.find('BCRYPT.DLL') != -1:
        crypt = 1

    if debug == 1:
        flag = 1
        print('Trying to evade debugger!\n')

    if crypt == 1:
        flag = 1
        print('Encryption detected!\n')

    if pr_esc > 1:
        flag = 1
        print('Privilege Escalation detected!\n')

    if proc_rep > 1:
        flag = 1
        print('Process Replacement detected!\n')

    if vm > 2:
        flag = 1
        print('Virtual Machine evading detected!\n')

    if flag == 0:
        print('The file passed static analysis successfully !!!')


if __name__ == '__main__':
    main()
