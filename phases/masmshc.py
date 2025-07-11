import re
import os
import logging
import io
from typing import List

logger = logging.getLogger("masmshc")

# original source: https://github.com/hasherezade/masm_shc/blob/master/masm_shc/main.cpp
# Converted to python by chatgpt, with some manual fixups


class Params:
    def __init__(self, infile, outfile, inline_strings, remove_crt, append_rsp_stub):
        self.infile = infile
        self.outfile = outfile
        self.inline_strings = inline_strings
        self.remove_crt = remove_crt
        self.append_rsp_stub = append_rsp_stub

def has_token(tokens, token):
    return token in tokens

def get_constant(consts_lines, tokens_line):
    for const_name, line in consts_lines.items():
        if any(token in tokens_line for token in [const_name]):
            return const_name
    return ""

def split_to_tokens(line):
    line = re.sub(r"[\t]", " ", line)
    tokens = line.split()
    for token in tokens:
        token = token.lstrip("FLAT:")
    return tokens

def append_align_rsp(ofile):
    stub = """
PUBLIC  AlignRSP
_TEXT SEGMENT
AlignRSP PROC
and  rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
call main ; Call the entry point of the payload
AlignRSP ENDP
_TEXT ENDS
"""

    stub2 = """
PUBLIC  AlignRSP
_TEXT SEGMENT
; AlignRSP - by @mattifestation (http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html)
; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload.This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment.When amd64
; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers(which require 16-byte)
; alignment.

AlignRSP PROC
push rsi ; Preserve RSI since we're stomping on it
mov  rsi, rsp ; Save the value of RSP so it can be restored
and  rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
sub  rsp, 020h ; Allocate homing space for ExecutePayload
call main ; Call the entry point of the payload
mov  rsp, rsi ; Restore the original value of RSP
pop  rsi ; Restore RSI
ret ; Return to caller

AlignRSP ENDP

_TEXT ENDS

"""
    ofile.write(stub)

def masm_shc(asm_text_lines: List[str]) -> str:
    g_is32bit = False
    consts_lines = {}
    seg_name = ""
    const_name = ""
    code_start = False

    params = Params("", "", 
        inline_strings=False,  # not for DATA_REUSE
        remove_crt=True, 
        append_rsp_stub=True)  # required atm
    ofile = io.StringIO()

    line_count = 0
    for line in asm_text_lines:
        line = line + "\n"  # lol
        tokens = split_to_tokens(line)

        if not tokens:
            ofile.write(line)
            continue

        if tokens[0] == ".686P":
            g_is32bit = True

        if tokens[0] == "EXTRN":
            raise Exception(f"[ERROR] Line {line_count + 1}: External dependency detected:\n{line}")

        in_skipped = False
        in_const = False

        if len(tokens) >= 2:
            # TMP better stack alignment
            #if tokens[0] == "sub" and tokens[1] == "rsp,":
            #    ofile.write(line)
            #    #ofile.write("\tand\trsp, 0FFFFFFFFFFFFFFF0h; Align RSP to 16 bytes\n")
            #    #ofile.write("\tsub\trsp, 8")
            #    continue

            if tokens[1] == "SEGMENT":
                seg_name = tokens[0]
                if not code_start and seg_name == "_TEXT":
                    code_start = True
                    if g_is32bit:
                        ofile.write("assume fs:nothing\n")
                    # TMP better stack alignment alternative
                    #else:
                    #    ofile.write("\tjmp\tmain\n")
                    elif params.append_rsp_stub:
                        append_align_rsp(ofile)
                        #logger.debug("[INFO] Entry Point: AlignRSP")

                if seg_name == "_BSS":
                    raise Exception(f"[ERROR] Line {line_count + 1}: _BSS segment detected! Remove all global and static variables!\n")

            if seg_name in ("pdata", "xdata", "voltbl"):
                in_skipped = True
            elif seg_name in ("CONST", "_DATA"):
                in_const = True
            elif tokens[1] == "ENDS" and tokens[0] == seg_name:
                seg_name = ""
                if in_const:
                    continue

        if in_skipped:
            continue

        if params.remove_crt and tokens[0] == "INCLUDELIB":
            if tokens[1] in ("LIBCMT", "OLDNAMES"):
                ofile.write(f"; {line}\n")  # copy commented out line
                continue
            raise Exception(f"[ERROR] Line {line_count + 1}: INCLUDELIB detected! Remove all external dependencies!\n")

        if params.inline_strings and in_const:
            if tokens[1] == "DB":
                const_name = tokens[0]
            if const_name != "":
                if const_name not in consts_lines:
                    consts_lines[const_name] = line
                else:
                    consts_lines[const_name] += "\n" + line
            continue

        if tokens[0] == "rex_jmp":
            line = re.sub(r"rex_jmp", "JMP", line)

        curr_const = get_constant(consts_lines, tokens)
        if params.inline_strings and curr_const != "":
            label_after = f"after_{curr_const}"
            ofile.write(f"\tCALL {label_after}\n")
            ofile.write(consts_lines[curr_const] + "\n")
            ofile.write(f"{label_after}:\n")
            if len(tokens) > 2 and (tokens[0] in ("lea", "mov")):
                offset_index = tokens.index("OFFSET", 1)
                instructions = tokens[1]
                if offset_index == 4:
                    instructions = f"{tokens[1]} {tokens[2]} {tokens[3]}"
                ofile.write(f"\tPOP  {instructions}\n")
            ofile.write("\n")
            ofile.write(f"; {line}\n")  # copy commented out line
            continue

        if not g_is32bit and any(token in tokens for token in ["gs:96"]):
            #line = re.sub(r"gs:96", "gs[96]\r\n", line)
            line = line.replace("gs:96", "gs:[96]")

        ofile.write(line)  # copy line

    if params.inline_strings:
        print("[INFO] Strings have been inlined. It may require to change some short jumps (jmp SHORT) into jumps (jmp)")

    return ofile.getvalue()
