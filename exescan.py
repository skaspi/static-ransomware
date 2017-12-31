#!/usr/bin/env python
import sys, pefile, re, peutils, os
from hashlib import md5, sha1, sha256

'''

Author: Amit Malik
E-Mail: m.amit30@gmail.com
(C)2011

Version: 2.6
Last Update: 16-09-2012 

'''


def help():
    print()
    print("Usage: prog [option] file/Directory")
    print("For eg: exescan.py -a malware.exe/malware")
    print("-a", "advanced scan with anomaly detection")
    print("-b", "display basic information")
    print("-m", "scan for commonly known malware APIs")
    print("-i", "display import/export table")
    print("-p", "display PE header")
    print()


def greet():
    log("\t\t**********************************************************")
    log("\t\t**           Author: Amit Malik (m.amit30@gmail.com)    **")
    log("\t\t**           http://www.SecurityXploded.com             **")
    log("\t\t**                                                      **")
    log("\t\t**********************************************************")


def log(data):
    global handle
    print(data)
    data = data
    nextline = "\n"
    handle.write(data)
    handle.write(nextline)
    return


def write_error(param):
    fh = open("out.txt", "a")
    fh.write(param)
    fh.close()


class ExeScan():
    def __init__(self, pe, file):
        self.pe = pe
        self.file = file
        self.MD5 = None
        self.SHA1 = None
        self.SHA256 = None
        self.data = None

    def hashes(self):
        f = open(self.file, "rb")
        self.data = f.read()
        self.MD5 = md5(self.data).hexdigest()
        self.SHA1 = sha1(self.data).hexdigest()
        self.SHA256 = sha256(self.data).hexdigest()
        f.close()
        return (self.MD5, self.SHA1, self.SHA256, self.data)

    def header(self):
        # header information check
        file_header = self.pe.FILE_HEADER.dump()
        log("\n")
        for i in file_header:
            log(i)
        nt_header = self.pe.NT_HEADERS.dump()
        log("\n")
        for i in nt_header:
            log(i)
        optional_header = self.pe.OPTIONAL_HEADER.dump()
        log("\n")
        for i in optional_header:
            log(i)
        log("\n")
        for i in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            i = i.dump()
            log("\n")
            for t in i:
                log(t)
        log("\n")
        for section in self.pe.sections:
            log("Name: %s\n" % section.Name)
            log('\tVirtual Size:            0x%.8x' % section.Misc_VirtualSize)
            log('\tVirtual Address:         0x%.8x' % section.VirtualAddress)
            log('\tSize of Raw Data:        0x%.8x' % section.SizeOfRawData)
            log('\tPointer To Raw Data:     0x%.8x' % section.PointerToRawData)
            log('\tPointer To Relocations:  0x%.8x' % section.PointerToRelocations)
            log('\tPointer To Linenumbers:  0x%.8x' % section.PointerToLinenumbers)
            log('\tNumber Of Relocations:   0x%.8x' % section.NumberOfRelocations)
            log('\tNumber Of Linenumbers:   0x%.8x' % section.NumberOfLinenumbers)
            log('\tCharacteristics:         0x%.8x\n' % section.Characteristics)

    def base(self, check):
        log("\n[+] Signature [Compiler/Packer]\n")
        if check:
            for i in check:
                log('\t%s' % i)
        else:
            log("\t[*] No match found.\n")

        log("\n[+] Address of entry point	: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        log("[+] Image Base Address		: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.ImageBase)
        log("[+] Sections")

        for section in self.pe.sections:
            print("here")
            log(
                "\tName: %s\t" % section.Name.strip().decode(
                    "utf-8") + "Virtual Address: 0x%.8x\t" % section.VirtualAddress + "Size: 0x%.8x\t" % section.Misc_VirtualSize + "Entropy: %f" % section.get_entropy())

            if ".text" in section.Name.strip().decode("utf-8"):
                if section.get_entropy() > 6.7:
                    write_error("1")

    def importtab(self):
        len_ = 0

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            log("\n[+] Imports\n")
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                log('\n[-] %s\n' % entry.dll.decode("utf-8"))
                for imp in entry.imports:
                    len_ += 1
                    log('\t0x%.8x\t%s' % (imp.address, imp.name.decode("utf-8")))

        if len_ < 5:
            write_error("2")

    def exporttab(self):
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            log("\n[+] Exports\n")
            for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                log('\t0x%.8x\t%s' % (entry.address, entry.name.decode("utf-8")))


def main_s(pe, ch, f, name):
    global handle
    exescan = ExeScan(pe, name)
    (MD5, SHA1, SHA256, data) = exescan.hashes()
    # store reports in folders
    if os.path.exists(MD5):
        report_name = str(MD5) + ".txt"
        report_name = os.path.join(MD5, report_name)
    else:
        os.mkdir(MD5)
        report_name = str(MD5) + ".txt"
        report_name = os.path.join(MD5, report_name)
    handle = open(report_name, 'a')
    greet()
    log("\n\n[+] File: %s" % name)
    log("\n\t[*] MD5 	: %s" % MD5)
    log("\t[*] SHA-1 	: %s" % SHA1)
    log("\t[*] SHA-256	: %s" % SHA256)
    # check file type (exe, dll)
    if pe.is_exe():
        log("\n[+] File Type: EXE")
    elif pe.is_dll():
        log("\n[+] File Type: DLL")
    strings = f.readlines()
    mf = open("API.txt", "r")
    MALAPI = mf.readlines()
    signature = peutils.SignatureDatabase("userdb.txt")
    check = signature.match_all(pe, ep_only=True)
    if ch == "-i":
        exescan.base(check)
        exescan.importtab()
        exescan.exporttab()

    else:
        print()
    mf.close()
    handle.close()
    return config.error


def main():
    if len(sys.argv) < 3:
        help()
        sys.exit(0)

    ch = sys.argv[1]
    fname = sys.argv[2]
    if os.path.isdir(fname):
        filelist = os.listdir(fname)
        for name in filelist:
            try:
                name = os.path.join(fname, name)
                pe = pefile.PE(name)
                f = open(name, "rb")
                new_name = main_s(pe, ch, f, name)
                f.close()
                pe.__data__.close()
                try:
                    new_name = new_name + ".bin"
                    new_name = os.path.join(fname, new_name)
                    os.rename(name, new_name)
                except:
                    pass
            except:
                pass
    else:
        try:
            fname = os.path.realpath(fname)
            print(fname)
            pe = pefile.PE(fname)
            f = open(fname, "rb")
            new_name = main_s(pe, ch, f, fname)
            f.close()
            pe.__data__.close()
            try:
                new_name = new_name + ".bin"
                os.rename(fname, new_name)
            except:
                pass
        except Exception:
            print("Done")
            # print ("Verbose: %s" % WHY)
            # sys.exit(0)


if __name__ == '__main__':
    main()
