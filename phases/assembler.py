import logging

from model import *
from config import config
from observer import observer
from pe.pehelper import *
from helper import *

logger = logging.getLogger("Assembler")


def asm_to_shellcode(asm_in: FilePath, build_exe: FilePath) -> bytes:
    """Takes ASM source file asm_in, compiles it into build_exe, extracts its code section and write into shellcode_out"""
    logger.info("-[ Carrier: ASM to EXE".format())
    logger.info("    Carrier: {} -> {}".format(asm_in, build_exe))
    run_process_checkret([
        config.get("path_ml64"),
        asm_in,
        "/link",
        "/OUT:{}".format(build_exe),
        "/entry:AlignRSP"  # "/entry:main",
    ])
    if not os.path.isfile(build_exe):
        raise Exception("Compiling failed")
    code = extract_code_from_exe_file(build_exe)
    logger.info("    Carrier Size: {}".format(
        len(code)
    ))
    return code


def encode_payload(payload: bytes, decoder_style: str) -> bytes:
    if decoder_style == "plain":
        return bytes(payload)
    elif decoder_style == "xor_1":
        xor_key = config.xor_key
        logger.debug("      XOR payload with key 0x{:X}".format(xor_key))
        xored = bytes([byte ^ xor_key for byte in payload])
        return bytes(xored)
    elif decoder_style == "xor_2":
        xor_key = config.xor_key2
        logger.debug("      XOR2 payload with key {}".format(xor_key))
        xored = bytearray(payload)
        for i in range(len(xored)):
            xored[i] ^= xor_key[i % 2]
        return bytes(xored)
    else:
        raise Exception("Unknown decoder style")
