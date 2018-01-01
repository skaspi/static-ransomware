#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Created on Mon Dec 11 15:12:16 2017

@authors Rafael,Dmitriy
Ransomware Detection Project
Technion, Haifa, Israel

The main script for static analysis.
- First of all, we check that the PE is not obfuscated, otherwise
  the static analysis DO NOT WORTH A THING.
  
  
- Next, we scan the PE for imported sys-calls, which give us a huge
  insight to the programm behavior:
      * Anti Debugging check
      * Anti VM check
      * Process Replacement check
      * Privilege Escalation check
      * Crypto-libraries presence check
  
"""
import os
import sys
import subprocess as sub


def main():
    str = os.path.splitext(sys.argv[1])[0] + ".txt"

    sub.Popen(["python", "exescan.py", "-i", sys.argv[1], ">", str], shell=True, stdout=sub.PIPE).communicate()[0]

    if os.path.exists('out.txt'):
        fh = open("out.txt", "r")
        data = fh.readline()

        if data == "12" or data == "2":
            print("The file was obfuscated!!")

        fh.close()
        os.remove("out.txt")

    else:
        sub.Popen(["python", "dependency.py", str, ">", "fin_static.txt"], shell=True, stdout=sub.PIPE).communicate()[0]

        with open("fin_static.txt", 'r') as fin:
            print(fin.read())

        fin.close()
        os.remove("fin_static.txt")

    os.remove(str)


if __name__ == '__main__':
    main()
