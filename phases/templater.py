from jinja2 import Template
import shutil
import logging
from typing import List

from helper import *
from observer import observer
from model.defs import *
from model.settings import Settings

logger = logging.getLogger("Assembler")


def get_template_names() -> List[str]:
    templates = []
    for filename in os.listdir(PATH_CARRIER):
        if filename.startswith("."):
            continue
        if filename == "common" or filename == "decoder":
            continue
        templates.append(filename)
    return templates


def create_c_from_template(settings: Settings, payload_len: int):
    plugin_decoder = ""

    src = "{}{}/".format(PATH_CARRIER, settings.carrier_name)
    dst = "{}{}/".format(PATH_WEB_PROJECT, settings.project_name)

    logger.info("-[ Create Carrier: {}".format(
        settings.project_c_path))
    
    # check that source directory exists
    if not os.path.exists(src):
        raise FileNotFoundError("Source directory does not exist: {}".format(src))

    # copy *.c *.h files from src directory to dst directory
    for file in os.listdir(src):
        if file.endswith(".c") or file.endswith(".h") or file.endswith(".res"):
            logger.debug("    Copy {} to {}".format(src + file, dst))
            shutil.copy2(src + file, dst)

    logger.info("    Carrier: {}".format(
        settings.carrier_name))
    logger.info("    Store payload in: {}".format(
        settings.payload_location.value))
    logger.info("    Use Decoder: {}".format(
        settings.decoder_style))
    logger.info("    Use Invoker: {}".format(
        settings.carrier_invoke_style.value))
    logger.info("    Use AntiEmulation: {}".format(
        settings.plugin_antiemulation)
    )
    logger.info("    Use MemoryObfuscation: {}".format(
        settings.plugin_memoryobfuscation)
    )
    if settings.dllfunc:
        logger.info("    DLL Function: {}".format(
            settings.dllfunc)
        )

    if settings.plugin_guardrail != "none":
        logger.info("    Carrier Guardrail: {}  (key: {}  value: {})".format(
            settings.plugin_guardrail, 
            settings.plugin_guardrail_data_key,
            settings.plugin_guardrail_data_value)
        )
    else:
        logger.info("    Carrier Guardrail: none")
    logger.info("    Carrier Decoy: {}".format(
        settings.plugin_decoy)
    )

    # Plugin: VirtualAlloc
    filepath_virtualprotect = PATH_VIRTUALPROTECT + "{}.c".format(
        settings.plugin_virtualprotect)
    with open(filepath_virtualprotect, "r", encoding='utf-8') as file:
        plugin_virtualprotect = file.read()
        plugin_virtualprotect = Template(plugin_virtualprotect).render({
            'virtualprotect_data': settings.plugin_virtualprotect_data,
        })

    # Plugin: Execution Guardrails
    filepath_guardrails = PATH_GUARDRAILS + "{}.c".format(
        settings.plugin_guardrail)
    with open(filepath_guardrails, "r", encoding='utf-8') as file:
        plugin_guardrails = file.read()
        plugin_guardrails = Template(plugin_guardrails).render({
            'guardrail_data_key': settings.plugin_guardrail_data_key,
            'guardrail_data_value': settings.plugin_guardrail_data_value,
        })

    # Plugin: Decoder
    filepath_decoder = PATH_DECODER + "{}.c".format(
        settings.decoder_style)
    with open(filepath_decoder, "r", encoding='utf-8') as file:
        plugin_decoder = file.read()
        plugin_decoder = Template(plugin_decoder).render({
            'PAYLOAD_LEN': payload_len,
            'XOR_KEY': config.xor_key,
            'XOR_KEY2': ascii_to_hex_bytes(config.xor_key2),
        })

    # Plugin: Anti-Emulation
    filepath_antiemulation = PATH_ANTIEMULATION + "{}.c".format(
        settings.plugin_antiemulation)
    with open(filepath_antiemulation, "r", encoding='utf-8') as file:
        sir_iteration_count = settings.sir_iteration_count
        sir_alloc_count = settings.sir_alloc_count
        max_alloc_count = 256
        if sir_alloc_count > max_alloc_count:
            # if too large, compiler will add a __checkstk dependency
            logger.warning("Too large sir allocation count {}, setting to max {}".format(
                sir_alloc_count, max_alloc_count
            ))
            sir_alloc_count = max_alloc_count
        logger.debug("-( AntiEmulation settings: iterations: {}  allocs: {}".format(
            sir_iteration_count, sir_alloc_count)
        )
        plugin_antiemualation = file.read()
        plugin_antiemualation = Template(plugin_antiemualation).render({
            'PAYLOAD_LEN': payload_len,
            'SIR_ALLOC_COUNT': sir_alloc_count,
            'SIR_ITERATION_COUNT': sir_iteration_count,
        })


    # Plugin: MemoryObfuscation
    filepath_memoryobfuscation = PATH_MEMORYOBFUSCATION + "{}.c".format(
        settings.plugin_memoryobfuscation)
    with open(filepath_memoryobfuscation, "r", encoding='utf-8') as file:
         process_spawn = settings.process_spawn
         sidecar_domain = settings.sidecar_domain
         sidecar_path = settings.sidecar_path
         plugin_memoryobfuscation = file.read()
         plugin_memoryobfuscation = Template(plugin_memoryobfuscation).render({
             'PROCESS_SPAWN': process_spawn,
             'SIDECAR_DOMAIN': sidecar_domain,
             'SIDECAR_PATH': sidecar_path,
         })

    # Plugin: Decoy
    filepath_decoy = PATH_DECOY + "{}.c".format(
        settings.plugin_decoy)
    with open(filepath_decoy, "r", encoding='utf-8') as file:
        plugin_decoy = file.read()

    # Choose template
    dirpath = PATH_CARRIER + settings.carrier_name + "/template.c"
    with open(dirpath, 'r', encoding='utf-8') as file:
        template_content = file.read()
        observer.add_text_file("main_c_template", template_content)
    # Render template
    template = Template(template_content)
    rendered_template = template.render({
        'plugin_decoder': plugin_decoder,
        'plugin_antiemulation': plugin_antiemualation,
        'plugin_memoryobfuscation': plugin_memoryobfuscation,
        'plugin_decoy': plugin_decoy,
        'plugin_executionguardrail': plugin_guardrails,
        'PAYLOAD_LEN': payload_len,
        'plugin_virtualprotect': plugin_virtualprotect,
    })
    with open(settings.project_c_path, "w", encoding='utf-8') as file:
        file.write(rendered_template)
        observer.add_text_file("main_c_rendered", rendered_template)
