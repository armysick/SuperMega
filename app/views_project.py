from flask import Flask, Blueprint, current_app, request, redirect, url_for, render_template, send_file, make_response, session, jsonify
from threading import Thread
import os
import logging
from typing import List, Tuple
from pygments import highlight
from pygments.lexers import CLexer, NasmLexer, DiffLexer, HexdumpLexer
from pygments.formatters import HtmlFormatter
import difflib
import subprocess
from ansi2html import Ansi2HTMLConverter
import pathlib

from observer import observer
from config import config
from model.settings import Settings
from model.defs import *
from supermega import start
from app.storage import storage
from model.project import Project
from sender import scannerDetectsBytes
from phases.injector import verify_injected_exe
from phases.templater import get_template_names
from helper import run_exe
from model.project import prepare_project
from pe.superpe import SuperPe 
import pe.dllresolver


logger = logging.getLogger("ViewsProjects")

views_project = Blueprint('views_project', __name__)

conv = Ansi2HTMLConverter()
config.load()
thread_running = False


@views_project.route("/projects")
def projects_route():
    project_settings = storage.get_project_settings()
    return render_template('projects.html', project_settings=project_settings)


@views_project.route("/project/<name>")
def project(name):
    project_setting = storage.get_project_setting(name)
    if project_setting == None:
        logger.error("Project {} not found".format(name))
        return redirect("/projects", code=302)
    #project_setting.print()
    
    is_built = False
    if os.path.exists(project_setting.get_inject_exe_out()):
        is_built = True

    exports = []
    is_64 = False
    is_dotnet = False
    code_sect_size = 0
    data_sect_size = 0
    data_sect_largest_gap_size = 0
    payload_len = 0
    unresolved_dlls = []
    has_remote = False
    has_rodata_section = False

    if config.get("avred_server") != "":
        has_remote = True

    # payload / shellcode
    if project_setting.get_payload_path() != None:
        payload_len = os.path.getsize(project_setting.get_payload_path())

    # injectable / exe
    if project_setting.get_inject_exe_in() != None and os.path.exists(project_setting.get_inject_exe_in()):
        superpe = SuperPe(project_setting.get_inject_exe_in())
        #if not superpe.is_64():
        #    # return 500
        #    return "Error: Binary {} is not 64bit".format(project.settings.get_inject_exe_in()), 500

        is_64 = superpe.is_64()
        is_dotnet = superpe.is_dotnet()
        if superpe.is_dll():
            exports = superpe.get_exports_full()
        code_sect_size = superpe.get_code_section().Misc_VirtualSize
        rdata_section = superpe.get_section_by_name(".rdata")
        if rdata_section != None:
            data_sect_size = rdata_section.virt_size
        else:
            logger.warning("No .rdata section found in {}".format(project_setting.get_inject_exe_in()))
        
        has_rodata_section = superpe.has_rodata_section()
        if has_rodata_section:
            data_sect_largest_gap_size = superpe.get_rdata_rangemanager().find_largest_gap()
        unresolved_dlls = pe.dllresolver.unresolved_dlls(superpe)

    project_dir = os.path.dirname(os.getcwd() + "\\" + project_setting.project_path)
    log_files = get_logfiles(project_setting.project_path)
    injectables = list_files_and_sizes(PATH_INJECTABLES)
    shellcodes = list_files_and_sizes(PATH_SHELLCODES)

    carrier_names = get_template_names()
    carrier_invoke_styles = [(color.name, color.value) for color in CarrierInvokeStyle]
    payload_locations = [(color.name, color.value) for color in PayloadLocation]

    guardrail_styles = list_files(PATH_GUARDRAILS)
    antiemulation_styles = list_files(PATH_ANTIEMULATION)
    memoryobfuscation_styles = list_files(PATH_MEMORYOBFUSCATION)
    decoy_styles = list_files(PATH_DECOY)
    virtualprotect_styles = list_files(PATH_VIRTUALPROTECT)
    decoder_styles = list_files(PATH_DECODER)

    return render_template('project.html', 
        project_name = name,
        project_comment = project_setting.project_comment,
        is_built=is_built,
        project_dir=project_dir,
        settings=project_setting,
        
        injectables=injectables,
        shellcodes=shellcodes,
        carrier_names=carrier_names,
        decoder_styles=decoder_styles,
        carrier_invoke_styles=carrier_invoke_styles,
        payload_locations=payload_locations,
        exports=exports,

        log_files=log_files,
        is_64=is_64,
        is_dotnet=is_dotnet,
        code_sect_size=code_sect_size,
        data_sect_size=data_sect_size,
        data_sect_largest_gap_size=data_sect_largest_gap_size,
        payload_len=payload_len,
        unresolved_dlls=unresolved_dlls,
        has_rodata_section=has_rodata_section,

        has_remote=has_remote,
        fix_missing_iat=project_setting.fix_missing_iat,

        guardrailstyles = guardrail_styles,
        antiemulationstyles = antiemulation_styles,
        memoryobfuscationstyles = memoryobfuscation_styles,
        decoystyles = decoy_styles,
        virtualprotectstyles = virtualprotect_styles
    )


def list_files_and_sizes(directory, prepend=""):
    # List all files in the directory and get their sizes
    files_and_sizes = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            size = os.path.getsize(filepath)
            files_and_sizes.append({
                "filename": prepend + filename,
                "size": size,
            })
    return files_and_sizes


def list_files(directory, prepend="") -> List[str]:
    files = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            filename = filename.replace(".c", "")
            files.append(filename)
    return files


@views_project.route("/project_add", methods=['POST', 'GET'])
def add_project():
    if request.method == 'POST':
        project_name = request.form['project_name']
        comment = request.form['comment']

        # check if already exists
        if storage.get_project_setting(project_name) != None:
            logger.error("Project {} already exists".format(project_name))
            return redirect("/projects", code=302)

        # Empty settings, except name
        settings = Settings(project_name)
        settings.project_comment = comment

        # Sane defaults for web
        settings.injectable_base = "7z.exe"
        settings.payload_base = "calc64.bin"

        settings.decoder_style = "xor_2"
        settings.carrier_name = "alloc_rw_rx"
        settings.carrier_invoke_style = CarrierInvokeStyle.BackdoorFunc
        settings.payload_location = PayloadLocation.DATA
        settings.fix_missing_iat = True
        settings.plugin_antiemulation = "sirallocalot"
        settings.plugin_memoryobfuscation = "spawn"
        settings.process_spawn = r"C:\\\\Windows\\\\System32\\\\notepad.exe"

        # add new project to disk
        storage.add_project_setting(settings)
        
        return redirect("/project/{}".format(project_name), code=302)
    
    else: # GET
        return render_template('project_add_get.html')
    

@views_project.route("/project_update", methods=['POST'])
def update_project():
    project_name = request.form['project_name']
    comment = request.form['comment']

    logger.info("Update project: {}".format(project_name))    
    settings: Settings|None = storage.get_project_setting(project_name)
    if settings == None:
        logger.error("Project {} not found".format(project_name))
        return redirect("/projects", code=302)
    
    shellcode_file = request.form['shellcode']
    injectable_file = request.form['exe']
    dll_func = request.form.get('dllfunc', "")

    settings.injectable_base = injectable_file
    settings.payload_base = shellcode_file
    settings.dllfunc = dll_func

    settings.fix_missing_iat = True if request.form.get('fix_missing_iat') != None else False
    settings.carrier_name = request.form['carrier_name']
    settings.plugin_antiemulation = request.form['antiemulation']
    settings.plugin_memoryobfuscation = request.form['memoryobfuscation']
    settings.plugin_decoy = request.form['decoy']
    settings.plugin_guardrail = request.form['guardrail']
    carrier_invoke_style = request.form['carrier_invoke_style']
    settings.carrier_invoke_style = CarrierInvokeStyle[carrier_invoke_style]
    settings.decoder_style = request.form['decoder_style']
    payload_location = request.form['payload_location']
    settings.payload_location = PayloadLocation[payload_location]
    settings.plugin_guardrail_data_key = request.form.get('guardrail_data_key', settings.plugin_guardrail_data_key)
    settings.plugin_guardrail_data_value = request.form.get('guardrail_data_value', settings.plugin_guardrail_data_value)
    settings.plugin_virtualprotect = request.form.get('virtualprotect', "standard")

    # overwrite project
    storage.save_project_settings(settings)

    return redirect("/project/{}".format(project_name), code=302)


def supermega_thread(settings: Settings):
    global thread_running
    start(settings)
    thread_running = False


@views_project.route("/project/<project_name>/build", methods=['POST', 'GET'])
def build_project(project_name):
    global thread_running

    project_settings = storage.get_project_setting(project_name)
    if project_settings == None:
        logger.error("Project {} not found".format(project_name))
        return redirect("/projects", code=302)
    
    pathlib.Path(project_settings.get_inject_exe_out()).unlink(missing_ok=True)

    #if project.settings.get_inject_exe_in().endswith(".dll"):
    #    if project.settings.dllfunc == "":
    #        logger.error("DLL injection requires a DLL function name")
    #        return redirect("/project/{}".format(project_name), code=302)

    project_settings.try_start_final_infected_exe = False
    project_settings.cleanup_files_on_start = True  # cleanup, or it will be confusing if failed

    project = Project(project_settings)
    prepare_project(project_name)
    thread = Thread(target=supermega_thread, args=(project.settings, ))
    thread.start()
    thread_running = True

    return redirect("/project/{}/status".format(project_name), code=302)


@views_project.route("/project/<project_name>/status")
def status_project(project_name):
    global thread_running
    if thread_running:
        return render_template('status_project.html', 
            project_name=project_name,
            logdata = "\n".join(observer.get_logs()))
    else:
        return redirect("/project/{}".format(project_name), code=302)


@views_project.route("/project/<project_name>/exec", methods=['POST', 'GET'])
def start_project(project_name):
    project_settings = storage.get_project_setting(project_name)
    if project_settings == None:
        return redirect("/", code=302)
    
    project = Project(project_settings)
    if not project.init():
        logger.error("Project {} could not be initialized".format(project_name))
        return redirect("/project/{}".format(project_name), code=302)

    remote = False
    remote_arg = request.args.get('remote')
    if remote_arg == "true":
        remote = True

    no_exec = False
    no_exec_arg = request.args.get('no_exec')
    if no_exec_arg == "true":
        no_exec = True

    logger.info("    Exec project: {} remote: {} no_exec: {}".format(project_name, remote, no_exec))

    if remote:
        logger.info("    Exec {} on server {}".format(project.settings.get_inject_exe_out(), config.get("avred_server")))
        with open(project.settings.get_inject_exe_out(), "rb") as f:
            data = f.read()
        filename = os.path.basename(project.settings.get_inject_exe_out())
        try:
            scannerDetectsBytes(data, 
                                filename, 
                                useBrotli=True, 
                                verify=project.settings.verify,
                                no_exec=no_exec)
        except Exception as e:
            logger.error(f'Error scanning: {e}')
            return jsonify({
				"exception": str(e)
			}), 500
    else:
        # Start/verify it at the end
        if project.settings.verify:
            logger.info("    Verify infected exe")
            exit_code = verify_injected_exe(project.settings.get_inject_exe_out())
        elif no_exec == False:
            run_exe(project.settings.get_inject_exe_out(), dllfunc=project.settings.dllfunc, check=False)
        elif no_exec == True:
            dirname = os.path.dirname(os.path.abspath(project.settings.get_inject_exe_out()))
            logger.info("    Open folder: {}".format(dirname))
            subprocess.run(['explorer', dirname])

    return redirect("/project/{}".format(project_name), code=302)


def get_logfiles(directory):
    log_files = []
    id = 0
    asm_a = ""  # for diff
    asm_b = ""
    for file in os.listdir(f"{directory}/"):
        if file.startswith("."):
            continue
        if not file.startswith("log-"):
            continue
        if file.endswith(".bin"):
            continue

        with open(os.path.join(f"{directory}/", file), "r") as f:
            data = f.read()
            if 'main_c' in file:
                data = highlight(data, CLexer(), HtmlFormatter(full=False))
            elif '_asm_' in file:
                # handle special cases
                if '_orig' in file:
                    asm_a = data
                if '_updated' in file:
                    asm_b = data
                data = highlight(data, NasmLexer(), HtmlFormatter(full=False))
            elif '.ascii' in file:
                data = conv.convert(data, full=False)
            elif '.txt' in file:
                continue # skip it 
            elif '.hex' in file:
                continue # skip it 
                #data = escape(data)
                #data = highlight(data, HexdumpLexer(), HtmlFormatter(full=False))
            elif '.log' in file:
                data = conv.convert(data, full=False)
            else:
                data = data

            entry = {
                "name": file,
                "id": str(id),
                "content": data,
            }
            log_files.append(entry)
            id += 1

            # more
            if asm_a != "" and asm_b != "":
                # do the diff from the content of the two files
                a = asm_a.splitlines()
                b = asm_b.splitlines()
                diff_generator = difflib.unified_diff(a, b, lineterm='')
                diff_string = '\n'.join(diff_generator)
                diff_l = highlight(diff_string, DiffLexer(), HtmlFormatter(full=False))
                entry = {
                    "name": "Summary: ASM Diff".format(),
                    "id": str(id),
                    "content": diff_l,
                }
                log_files.append(entry)
                id += 1
                #asm_a = ""
                asm_b = ""
    return log_files
