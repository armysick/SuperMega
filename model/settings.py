import logging
from model.defs import *

logger = logging.getLogger("Views")


class Settings():
    def __init__(self, project_name: str = "default"):
        self.project_name: str = project_name
        self.project_comment: str = ""
        self.project_path: FilePath = FilePath("{}{}/".format(PATH_WEB_PROJECT, self.project_name))

        # OUT: Project directories and files (based on project_path)
        self.project_c_path: FilePath = FilePath(self.project_path + "main.c")
        self.project_asm_path: FilePath = FilePath(self.project_path + "main.asm")
        self.project_exe_path: FilePath = FilePath(self.project_path + "main.exe")
        self.project_shc_path: FilePath = FilePath(self.project_path + "main.bin")
        
        # IN: Injectable (like "7z.exe", in data/input/injectables/)
        self.injectable_base: str = ""
        # IN: Payload / Shellcode (like "createfile.bin", in data/input/shellcodes/)
        self.payload_base: str = ""

        # Config
        self.carrier_name: str = ""
        self.carrier_invoke_style: CarrierInvokeStyle = CarrierInvokeStyle.BackdoorFunc
        self.decoder_style: str = "xor_2"
        self.payload_location: PayloadLocation = PayloadLocation.DATA
        self.short_call_patching: bool = False
        self.fix_missing_iat = True
        self.patch_show_window = True
        self.dllfunc: str = ""  # For DLL injection

        # PLUGIN: Guardrail
        self.plugin_guardrail: str = "none"
        self.plugin_guardrail_data_key: str = ""
        self.plugin_guardrail_data_value: str = ""

        # PLUGIN: Anti-Emulation / EDR deconditioner
        self.plugin_antiemulation: str = "none"
        self.sir_iteration_count: int = 5
        self.sir_alloc_count: int = 100

        # PLUGIN: Memory Obfuscation
        self.plugin_memoryobfuscation: str = "none"
        self.process_spawn: str = "none"
        self.sidecar_domain: str = "none"
        self.sidecar_path: str = "none"

        # PLUGIN: Other (not widely used or important)
        self.plugin_virtualprotect: str = "standard"
        self.plugin_virtualprotect_data: str = ""
        self.plugin_decoy: str = "none"

        # DEBUG: Debug stuff (for development)
        self.show_command_output: bool = False
        self.verify: bool = False
        self.try_start_final_infected_exe: bool = False
        self.cleanup_files_on_start: bool = True
        self.cleanup_files_on_exit: bool = True
        self.generate_asm_from_c: bool = True

    def get_payload_path(self) -> FilePath:
        if self.payload_base == "":
            return None
        return FilePath(PATH_SHELLCODES + self.payload_base)
    
    def get_inject_exe_in(self) -> FilePath:
        if self.injectable_base == "":
            return None
        return FilePath(PATH_INJECTABLES + self.injectable_base)
    
    def get_inject_exe_out(self) -> FilePath:
        return FilePath("{}{}".format(
            self.project_path,
            self.injectable_base.replace(".exe", ".infected.exe")
        ))

    def print(self):
        logger.info("Settings for project: {}".format(self.project_name))
        for attr, value in self.__dict__.items():
            if isinstance(value, FilePath):
                value = str(value)
            logger.info("  {}: {}".format(attr, value))
        logger.info("-" * 40)
