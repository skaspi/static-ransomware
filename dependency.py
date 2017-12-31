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
import mmap
import sys


def main():
    crypt, VM, proc_rep, pr_esc, debug = 0, 0, 0, 0, 0

    with open(sys.argv[1], 'rb', 0) as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as s:

        # Anti Debugging check
        if s.find(b'IsDebuggerPresent') != -1:
            debug = 1

            # Anti VM check
        if s.find(b'GetCursorPos') != -1:
            VM += 1
        if s.find(b'GetUserName') != -1:
            VM += 1
        if s.find(b'GetModuleFileName') != -1:
            VM += 1
        if s.find(b'GetLogicalDriveStrings') != -1:
            VM += 1
        if s.find(b'GetDriveType') != -1:
            VM += 1
        if s.find(b'DeviceIoControl') != -1:
            VM += 1
        if s.find(b'GetSystemInfo') != -1:
            VM += 1
        if s.find(b'GlobalMemoryStatusEx') != -1:
            VM += 1
        if s.find(b'GetModuleHandleA') != -1:
            VM += 1
        if s.find(b'GetAdaptersAddresses') != -1:
            VM += 1

            # Process Replacement check
        if s.find(b'CreateFileMapping') != -1:
            proc_rep += 1
        if s.find(b'MapViewOfFile') != -1:
            proc_rep += 1
        if s.find(b'WriteProcessMemory') != -1:
            proc_rep += 1
        if s.find(b'VirtualAllocEx') != -1:
            proc_rep += 1

            # Privilege Escalation check
        if s.find(b'AdjustTokenPrivileges') != -1:
            pr_esc += 1
        if s.find(b'OpenProcessToken') != -1:
            pr_esc += 1

            # Crypto-libraries presence check
        if s.find(b'CryptDecrypt') != -1:
            crypt = 1
        if s.find(b'NCRYPT.DLL') != -1:
            crypt = 1
        if s.find(b'BCRYPT.DLL') != -1:
            crypt = 1
        if s.find(b'CRYPTSP.DLL') != -1:
            crypt = 1

        if debug == 1:
            print('Trying to evade debugger!\n')

        if crypt == 1:
            print('Encryption detected!\n')

        if pr_esc > 1:
            print('Privilege Escalation detected!\n')

        if proc_rep > 1:
            print('Process Replacement detected!\n')

        if VM > 2:
            print('Virtual Machine evading detected!\n')

        tup = (crypt, VM, proc_rep, pr_esc, debug)
        sum_ = 0

        for n in tup:
            sum_ += n

        if sum_ < 5:
            print('The file passed static analysis successfully !!!')


if __name__ == '__main__':
    main()
