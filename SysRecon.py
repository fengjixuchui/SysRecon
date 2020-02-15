#!/usr/bin/env python3

import argparse
import hashlib
import os

# vuln drivers according to https://github.com/eclypsium/Screwed-Drivers/blob/master/DRIVERS.md
# feel free to update please
dict = {'b4d47ea790920a4531e3df5a4b4b0721b7fea6b49a35679f0652f1e590422602': 'AsUpIO64.sys', 'ece0a900ea089e730741499614c0917432246ceb5e11599ee3a1bb679e24fd2c': 'AsrDrv10.sys', 'f40435488389b4fb3b945ca21a8325a51e1b5f80f045ab019748d0ec66056a8b': 'AsrDrv101.sys', 'a7c2e7910942dd5e43e2f4eb159bcd2b4e71366e34a68109548b9fb12ac0f7cc': 'AsrDrv102.sys', '2003b478b9fd1b3d76ec5bf4172c2e8915babbbee7ad1783794acbf8d4c2519d': 'AsrDrv103.sys', 'f929bead59e9424ab90427b379dcdd63fbfe0c4fb5e1792e3a1685541cd5ec65': 'BSMEMx64.sys', '59626cac380d8fe0b80a6d4c4406d62ba0683a2f0f68d50ad506ca1b1cf25347': 'BSMIXP64.sys', '552f70374715e70c4ade591d65177be2539ec60f751223680dfaccb9e0be0ed9': 'BSMIx64.sys', '86a8e0aa29a5b52c84921188cc1f0eca9a7904dcfe09544602933d8377720219': 'BS_Flash64.sys', '1d0397c263d51e9fc95bcc8baf98d1a853e1c0401cd0e27c7bf5da3fba1c93a8': 'BS_HWMIO64_W10.sys', '60c6f4f34c7319cb3f9ca682e59d92711a05a2688badbae4891b1303cd384813': 'BS_HWMIo64.sys', '55fee54c0d0d873724864dc0b2a10b38b7f40300ee9cae4d9baaf8a202c4049a': 'BS_I2c64.sys', '61a1bdddd3c512e681818debb5bee94db701768fc25e674fcad46592a3259bd0': 'GLCKIO2.sys', '42f0b036687cbd7717c9efed6991c00d4e3e7b032dc965a2556c02177dfdad0f': 'GVCIDrv64.sys', 'bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc': 'HwOs2Ec10x64.sys', 'b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de': 'HwOs2Ec7x64.sys', '525d9b51a80ca0cd4c5889a96f857e73f3a80da1ffbae59851e0f51bdfb0b6cd': 'MsIo64.sys', '3f2fda9a7a9c57b7138687bbce49a2e156d6095dddabb3454ea09737e02c3fa5': 'NBIOLib_X64.sys', '314384b40626800b1cde6fbc51ebc7d13e91398be2688c2a58354aa08d00b073': 'NCHGBIOS2x64.SYS', 'd8b58f6a89a7618558e37afc360cd772b6731e3ba367f8d58734ecee2244a530': 'NTIOLib_X64.sys', '65db1b259e305a52042e07e111f4fa4af16542c8bacd33655f753ef642228890': 'PhlashNT.sys', '19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0': 'Phymemx64.sys', 'a7c8f4faf3cbb088cac7753d81f8ec4c38ccb97cd9da817741f49272e8d01200': 'UCOREW64.SYS', '677c0b1add3990fad51f492553d3533115c50a242a919437ccb145943011d2bf': 'WinFlash64.sys', '11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5': 'WinRing0x64.sys', 'fc22977ff721b3d718b71c42440ee2d8a144f3fbc7755e4331ddd5bcc65158d2': 'amifldrv64.sys', 'ad40e6d0f77c0e579fb87c5106bf6de3d1a9f30ee2fbf8c9c011f377fa05f173': 'atillk64.sys', '18e1707b319c279c7e0204074088cc39286007a1cf6cb6e269d5067d8d0628c6': 'dbk64.sys', 'c9cf1d627078f63a36bbde364cd0d5f2be1714124d186c06db5bcdf549a109f8': 'mtcBSv64.sys', 'afdd66562dea51001c3a9de300f91fc3eb965d6848dfce92ccb9b75853e02508': 'nvflash.sys', 'a899b659b08fbae30b182443be8ffb6a6471c1d0497b52293061754886a937a3': 'nvflsh64.sys', '1963d5a0e512b72353953aadbe694f73a9a576f0241a988378fa40bf574eda52': 'phymem64.sys', '7133a461aeb03b4d69d43f3d26cd1a9e3ee01694e97a0645a3d8aa1a44c39129': 'rtkio64.sys', '32e1a8513eee746d17eb5402fb9d8ff9507fb6e1238e7ff06f7a5c50ff3df993': 'rtkiow10x64.sys', '082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d': 'rtkiow8x64.sys', '65329dad28e92f4bcc64de15c552b6ef424494028b18875b7dba840053bc0cdd': 'segwindrvx64.sys', 'f8430bdc6fd01f42217d66d87a3ef6f66cb2700ebb39c4f25c8b851858cc4b35': 'superbmc.sys', '9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33': 'semav6msr.sys', 'b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29': 'piddrv64.sys'}


# arg parsing
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--sys", type=str, nargs="?", help="relative path to driver filename to check")
parser.add_argument("-f", "--file", default=None, type=str, nargs="?", help="relative path to line-separated list of driver filenames to check")
parser.add_argument("-r", "--recon", action="store_true", help="scan for .sys files starting from C:\\ directory")

args = parser.parse_args()
sys = args.sys
sys_file = args.file
if args.recon:
    command_string = "cd C:\\ && dir /s /b *.sys"

# just seeing if the hash is in our dict for a single .sys
def single_sys(sys):
    try:
        sha256_hash = hashlib.sha256()
        with open(sys,"rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            digest = (sha256_hash.hexdigest())
            if digest in dict:
                print("[!] Hash found, RIP. Associated with file: {}".format(dict[digest]))
            else:
                print("[*] Hash not found!")
    except Exception as e:
        print(e)

# opening the specified file and parsing each newline separated value to see if we have hashes
def file_parse(sys_file):
    try:
        found = []
        not_found = []
        r = open(sys_file,"r")
        for lines in r:
            lines = lines.rstrip("\n")
            sha256_hash = hashlib.sha256()
            with open(lines,"rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
                digest = (sha256_hash.hexdigest())
                if digest in dict:
                    found.append(dict[digest])
                else:
                    not_found.append(lines)
        if found:
            print("[!] Hashes found for the following drivers:")
            for x in found:
                print(x)
        if not_found:
            print("[*] Hashes not found for the following drivers:")
            for x in not_found:
                print(x)
        r.close()
    except Exception as e:
        print("[!] Something went wrong parsing the file\n")
        print(e)

# doing recon and writing every found file path to a driver to a temp file and then basically running file_parse() on the temp file
def recon_func():
    try:
        print("[*] Scanning file system from C:\\ for .sys files...")
        found = []
        not_found = []
        results = os.popen(command_string).read()
        results = results.split("\n")
        sha256_hash = hashlib.sha256()
        for x in results:
            try:
                if x[-4:] != ".sys":
                    continue
                with open(x,"rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        sha256_hash.update(byte_block)
                    digest = (sha256_hash.hexdigest())
                    if digest in dict:
                        found.append(x)
                    else:
                        not_found.append(x)

            except Exception as e:
                print(e)

        if len(found) <= 20:
            print("[!] Found {} vulnerable drivers:\n".format(len(found)))
            for x in found:
                print(x)
        else:
            print("[!] Found more than 20 vulnerable drivers, outputting results to VulnerableDrivers.txt, Oof.\n")
            fnd = open("VulnerableDrivers.txt","a+")
            for x in found:
                fnd.write(x + "\n")
            fnd.close()
        
        if len(not_found) <=20:
            print("\n[*] Found {} potential bug-hunt-friendly drivers:".format(len(not_found)))
            for x in not_found:
                print(x)
        else:
            print("\n[*] Found more than 20 potentially bug-hunt-friendly drivers, outputting results to DriverBugHunt.txt")
            ufnd = open("DriverBugHunt.txt","a+")
            for x in not_found:
                ufnd.write(x + "\n")
            ufnd.close()

    except Exception as e:
        print(e)

if __name__=='__main__':
    print('\n')
    print("  plz let us find     >o)")
    print("   a driver 2 hunt    (_>)")
    print('\n')
    if sys:
        single_sys(sys)
    elif sys_file:
        file_parse(sys_file)
    elif args.recon:
        recon_func()
