from enum import Enum
import os


# FilePath type for better clarity in the code
class FilePath(str):
    pass


# for data/shellcodes/createfile.bin
VerifyFilename: FilePath = FilePath("C:\\Temp\\a")

# Input Binary
PATH_INJECTABLES = "data/binary/injectables/"
PATH_SHELLCODES = "data/binary/shellcodes/"

# Input Source
PATH_CARRIER = "data/source/carrier/"
PATH_DECODER = "data/source/decoder/"
PATH_ANTIEMULATION = "data/source/antiemulation/"
PATH_MEMORYOBFUSCATION = "data/source/memoryobfuscation/"
PATH_DECOY = "data/source/decoy/"
PATH_GUARDRAILS = "data/source/guardrails/"
PATH_VIRTUALPROTECT = "data/source/virtualprotect/"

# Project settings
PATH_WEB_PROJECT = "projects/"


CODE_INJECT_SIZE_CHECK_ADD = 128

class PayloadLocation(Enum):
    CODE = ".text"
    DATA = ".rdata"


class CarrierInvokeStyle(Enum):
    OverwriteFunc = "Overwrite Function"
    BackdoorFunc = "Backdoor Function"

    
class PeRelocEntry():
    def __init__(self, rva: int, base_rva: int, type: str):
        self.rva: int = rva
        self.base_rva: int = base_rva
        self.offset: int = rva - base_rva
        self.type: str = type


    def __str__(self):
        return "PeRelocEntry: rva: 0x{:X} base_rva: 0x{:X} offset: 0x{:X} type: {}".format(
            self.rva, self.base_rva, self.offset, self.type)


class IatEntry():
    def __init__(self, dll_name: str, func_name: str, iat_vaddr: int):
        self.dll_name: str = dll_name
        self.func_name: str = func_name
        self.iat_vaddr: int = iat_vaddr

    def __str__(self):
        return "IatEntry: dll_name: {} func_name: {} iat_vaddr: 0x{:X}".format(
            self.dll_name, self.func_name, self.iat_vaddr)
