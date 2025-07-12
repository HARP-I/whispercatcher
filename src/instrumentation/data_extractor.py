import frida
import json
import re
import os, sys
import time
import subprocess
import math
import random
import magic
from loguru import logger
from multiprocessing import Process, Event, Queue
from traffic.capture_traffic import grant_permissions, prepare_apk
from config import hook_output_dir, key_apis_output_dir, adb_client, device, WAIT_FOR_DATA_TRANSMISSION
from utils import (
    apk_install,
    adb_forwards,
    adb_uninstall,
    prepare_apk,
    grant_permissions,
    check_permission_full_screen_window,
    run_frida,
    check_device_connection,
    wake_up_device_if_shutdown,
    reformat_data_map,
)

magic_inference = magic.Magic(mime=True)


def java_type_convert(java_type):
    primitive_types_map = {
        "boolean": "Z",
        "byte": "B",
        "char": "C",
        "short": "S",
        "int": "I",
        "long": "J",
        "float": "F",
        "double": "D",
        "void": "V",
    }
    array_dim = java_type.count("[]")
    base_type = java_type.replace("[]", "")
    if array_dim > 0 and base_type in primitive_types_map:
        return "[" * array_dim + primitive_types_map[base_type]
    elif array_dim > 0 and base_type not in primitive_types_map:
        return "[" * array_dim + "L" + base_type + ";"
    else:
        return java_type


def parse_apis_lst_with_types(apis_lst, shuffle=True):
    keywords = ["java.lang.String", "java.util.Map", "java.util.List", "byte[]", "org.json.JSONObject", "java.io.File"]

    apis_lst = filter(
        lambda api: not api.startswith("kotlin")
        and not api.startswith("kotlinx")
        and not api.startswith("java.lang.Class")
        and not api.startswith("java.lang.reflect")
        and not api.lower().find("sqlite") >= 0
        and not api.lower().find("<init>") >= 0
        and not api.lower().find("<clinit>") >= 0,
        apis_lst,
    )
    apis_lst = list(set(apis_lst))
    new_apis_lst = []
    for api in apis_lst:
        if not any(keyword in api for keyword in keywords):
            continue
        signature = api[: api.find("(")]
        params_str = api[api.find("(") + 1 : api.find(")")]
        return_str = api[api.find(": ") + 2 :]
        params_lst = [param.strip() for param in params_str.split(",") if param.strip()]
        params_lst = [java_type_convert(param) for param in params_lst]
        return_str = java_type_convert(return_str)
        new_apis_lst.append(f"{signature}({', '.join(params_lst)}){': ' + return_str if return_str else ''}")
    if shuffle:
        if shuffle:
            random.shuffle(new_apis_lst)
        return new_apis_lst
    return new_apis_lst


def construct_hook_script_with_types(parsed_apis, hook_script):
    def map_to_frida_script(parsed_apis, template_entry="testMethod"):
        stmts = []
        for full_sign in parsed_apis:
            paramsArray = [item for item in full_sign[full_sign.index("(") + 1 : full_sign.index(")")].split(", ") if len(item) > 0]
            classMethod = full_sign[: full_sign.index("(")]
            s = classMethod.split(".")
            className = ".".join(s[:-1])
            methodName = s[-1]
            invokeCnt = 0
            stmts.append({"className": className, "methodName": methodName, "paramsArray": paramsArray, "invokeCnt": invokeCnt})
        return "\n".join([f"{template_entry}({stmt});" for stmt in stmts])

    return re.sub("toBeCompleted", map_to_frida_script(parsed_apis), hook_script)


def start_frida_service_for_batch_run(key_apis_batch, logger_config, recorder_files_lst, package_name, exit_event, comm_queue, time_out):
    def on_frida_message(message, data):
        # all_loaded_classes_recorder, hooked_methods_recorder, data_map_recorder = recorders_lst[0], recorders_lst[1], recorders_lst[2]
        if message["type"] == "error":
            frida_service_logger.error(f"[hook_analyzer] Frida responses error message: {message}")
            return
        msg = json.loads(message["payload"])
        if "all_loaded_classes" in msg.keys():
            frida_service_logger.info(f"[hook_analyzer] Frida responses all loaded classes...")
            data_recv = msg["all_loaded_classes"]
            all_loaded_classes_recorder.info(json.dumps(data_recv, indent=4, ensure_ascii=False))
        elif "hook_method" in msg.keys():
            frida_service_logger.info(f"[hook_analyzer] Frida responses hooked methods...")
            data_recv = msg["hook_method"]
            hooked_methods_recorder.info(json.dumps(data_recv, indent=4, ensure_ascii=False) + ",")
        else:  # msg == "method_call"
            frida_service_logger.info(f"[hook_analyzer] Frida responses called methods and data...")
            data_recv = msg["method_call"]
            if data_recv["args"] is not None:
                if str(data_recv["api"]).endswith("write"):
                    if type(data_recv["args"]) == list and all(elem.isdigit() for elem in data_recv["args"][0].split(",")):
                        data_recv["args"][0] = "".join([chr(int(i)) if 0 <= int(i) <= 0xFFFF else "?" for i in data_recv["args"][0].split(",")])
            data_map_recorder.info(json.dumps(data_recv, indent=4, ensure_ascii=False) + ",")
            frida_service_logger.info(f"[hook_analyzer] [called method: {data_recv['api']}, data_type: args ] -> {str(data_recv['args'])}")
            ret_value = str(data_recv["ret"]) if "ret" in data_recv.keys() else None
            frida_service_logger.info(f"[hook_analyzer] [called method: {data_recv['api']}, data_type: ret ] -> {ret_value}")
            frida_service_logger.info(f"[hook_analyzer] [called method: {data_recv['api']}, data_type: stack ] -> {str(data_recv['stack'])}")

    # create frida service logger
    frida_service_logger = logger.bind(name=logger_config["bind_name"])
    frida_service_console_logger_id = frida_service_logger.add(
        sys.stdout, format=logger_config["format"], enqueue=True, filter=lambda msg: msg["extra"].get("name") == logger_config["bind_name"]
    )
    frida_service_file_logger_id = frida_service_logger.add(
        logger_config["file_sink"],
        format=logger_config["format"],
        enqueue=True,
        encoding="utf-8",
        filter=lambda msg: msg["extra"].get("name") == logger_config["bind_name"],
    )

    # init recorders
    all_loaded_classes_file_path, hooked_methods_file_path, data_map_file_path = recorder_files_lst[0], recorder_files_lst[1], recorder_files_lst[2]
    all_loaded_classes_recorder = frida_service_logger.bind(name="all_loaded_classes_recorder")
    all_loaded_classes_recorder_id = all_loaded_classes_recorder.add(
        all_loaded_classes_file_path,
        format="{message}",
        encoding="utf-8",
        enqueue=True,
        serialize=False,
        backtrace=False,
        diagnose=False,
        mode="w",
        filter=lambda msg: msg["extra"].get("name") == "all_loaded_classes_recorder",
    )
    hooked_methods_recorder = frida_service_logger.bind(name="hooked_methods_recorder")
    hooked_methods_recorder_id = hooked_methods_recorder.add(
        hooked_methods_file_path,
        format="{message}",
        encoding="utf-8",
        enqueue=True,
        serialize=False,
        backtrace=False,
        diagnose=False,
        mode="a",
        filter=lambda msg: msg["extra"].get("name") == "hooked_methods_recorder",
    )
    data_map_recorder = frida_service_logger.bind(name="data_map_recorder")
    data_map_recorder_id = data_map_recorder.add(
        data_map_file_path,
        format="{message}",
        encoding="utf-8",
        enqueue=True,
        serialize=False,
        backtrace=False,
        diagnose=False,
        mode="a",
        filter=lambda msg: msg["extra"].get("name") == "data_map_recorder",
    )
    try:
        # spawn app
        remote_device = frida.get_remote_device()
        try:
            pid = remote_device.spawn([package_name])
        except frida.TimedOutError:
            permission_page = check_permission_full_screen_window(adb_client, device)
            if permission_page:
                frida_service_logger.info(f"[hook_analyzer] frida time out because of permission page, skip.")
                return
            else:
                frida_service_logger.error(f"[hook_analyzer] frida time out.")
                raise frida.TimedOutError("unexpectedly timed out while waiting for app to launch")
        session = remote_device.attach(pid)
        frida_service_logger.info(f"[hook_analyzer] Spawning app through frida... | pid = {pid} | package_name = {package_name}")

        # load hook script and start instrumentation
        frida_service_logger.info(f"[hook_analyzer] Loading hook script...")
        with open("src/hookscript/network_related_with_params.js", encoding="utf-8") as source_file:
            base_hook_script = source_file.read()
        hook_script = construct_hook_script_with_types(key_apis_batch, base_hook_script)
        frida_service_logger.info(f"[hook_analyzer] Key apis batch length: {len(key_apis_batch)}, starting instrumentation...")
        script = session.create_script(hook_script)
        script.on("message", on_frida_message)
        script.load()
        remote_device.resume(pid)

        # wait for termination
        start_time = time.time()
        finish_time = time.time()
        while not exit_event.is_set() and finish_time - start_time < time_out:
            time.sleep(1)
            finish_time = time.time()
        else:
            all_loaded_classes_recorder.remove(all_loaded_classes_recorder_id)
            hooked_methods_recorder.remove(hooked_methods_recorder_id)
            data_map_recorder.remove(data_map_recorder_id)
            logger.remove(frida_service_console_logger_id)
            logger.remove(frida_service_file_logger_id)
            session.detach()

        # handle timeout
        if finish_time - start_time >= time_out:
            frida_service_logger.error(f"[hook_analyzer] Frida service timeout...")
            comm_queue.put(TimeoutError("Frida service timeout..."))

    except Exception as e:
        frida_service_logger.error(f"[hook_analyzer] Failed to start instrumentation... | Error = {e}")
        comm_queue.put(e)
        sys.exit(1)


def batch_run_frida_service(
    apk_path,
    key_apis_path,
    logger_config,
    recorder_files,
    pkg_name,
    batch_logger,
    frida_server_handler,
    frida_path="/data/local/tmp/fs16.1.5arm64",
    apis_batch_size=64,
    batch_wait_time_sec=WAIT_FOR_DATA_TRANSMISSION,
):
    apis_lst = []
    with open(key_apis_path, encoding="utf-8") as api_file:
        apis_json = json.load(api_file)
        for _, item_apis_lst in apis_json.items():
            apis_lst += item_apis_lst
    parsed_apis = parse_apis_lst_with_types(apis_lst)  # with types
    apis_cnt = 0

    # set batch size dynamically
    if len(parsed_apis) >= 100 and len(parsed_apis) < 200:
        apis_batch_size = 30
    elif len(parsed_apis) < 1000:
        apis_batch_size = 50
    else:
        apis_batch_size = 80

    while apis_cnt < len(parsed_apis):
        try:
            batch_apis = parsed_apis[apis_cnt : min(apis_cnt + apis_batch_size, len(parsed_apis))]
            apis_cnt += len(batch_apis)

            batch_logger.info(
                f"[hook_analyzer] Starting {math.ceil(apis_cnt / apis_batch_size)}/{math.ceil(len(parsed_apis)/apis_batch_size)} batch run for {pkg_name} with {len(batch_apis)} apis..."
            )
            frida_batch_service_exit_event = Event()
            frida_service_comm_queue = Queue()
            frida_batch_hook_handler = Process(
                target=start_frida_service_for_batch_run,
                args=(batch_apis, logger_config, recorder_files, pkg_name, frida_batch_service_exit_event, frida_service_comm_queue, batch_wait_time_sec * 2),
            )
            frida_batch_hook_handler.start()
            batch_logger.info(f"[hook_analyzer] Wait for data transmission...")
            time.sleep(batch_wait_time_sec)

            # check if frida service has errors
            if not frida_service_comm_queue.empty():
                err = frida_service_comm_queue.get()
                batch_logger.error(f"[hook_analyzer] Frida batch service error: {err}")
                frida_server_handler.terminate()
                time.sleep(15)
                batch_logger.info(f"[hook_analyzer] try to wake up device (from batch frida service)...")
                wake_up_device_if_shutdown(adb_client, device, frida_path)
                logger.info(f"[hook_analyzer] Executing adb forwards...")
                adb_forwards(device, logger)
                logger.info(f"[hook_analyzer] Restarting frida server...")
                frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
                frida_server_handler.start()

            batch_logger.info(f"[hook_analyzer] Terminate batch frida service...")
            frida_batch_service_exit_event.set()
            frida_batch_hook_handler.join(timeout=5)
            if frida_batch_hook_handler.is_alive():
                frida_batch_hook_handler.terminate()
            time.sleep(2)
            batch_logger.info(f"[hook_analyzer] reinstall app - {pkg_name}...")
            # reinstall app or clear app data
            # adb_uninstall(pkg_name, device)
            # time.sleep(2)
            # apk_install(apk_path, device, frida_path)
            # time.sleep(2)
            device.shell(f"pm clear {pkg_name}")  # clear app data
        except Exception as e:
            batch_logger.error(f"[hook_analyzer] Failed to run batch frida service... | Error = {e}")
            frida_server_handler.terminate()
            time.sleep(30)
            batch_logger.info(f"[hook_analyzer] try to wake up device (from batch frida service)...")
            wake_up_device_if_shutdown(adb_client, device, frida_path)
            logger.info(f"[hook_analyzer] Executing adb forwards...")
            adb_forwards(device, logger)
            logger.info(f"[hook_analyzer] Restarting frida server...")
            frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
            frida_server_handler.start()

    logger.info(f"[hook_analyzer] Uninstalling apk from device (batch run)... | Apk = {apk_path} | Pkg = {pkg_name}")
    adb_uninstall(pkg_name, device)


def dynamic_analyzer(
    apk_path,
    pkg_name,
    apk_name,
    key_apis_path,
    timer,
    adb_client,
    device,
    logger,
    logger_config,
    frida_server_handler=None,
    frida_path="/data/local/tmp/fs16.1.5arm64",
):
    if not os.path.exists(key_apis_path):
        logger.info(f"[hook_analyzer] Key apis file not found. | File = {key_apis_path}")
        return
    with open(key_apis_path, "r", encoding="utf-8") as f:
        key_apis_json = json.load(f)
    if len(key_apis_json) == 0:
        logger.info(f"[hook_analyzer] No key apis found in the file, skip this apk... | Apk = {apk_path} | Pkg = {pkg_name}")
        return
    logger.info(f"[hook_analyzer] Start hook analyzer... | Apk = {apk_path} | Pkg = {pkg_name} | Timer = {timer}")
    logger.info(f"[hook_analyzer] Check device connections...")
    check_device_connection(logger)

    try:
        logger.info(f"[hook_analyzer] Installing apk to device... | Apk = {apk_path}")
        apk_install(apk_path, device, frida_path)
    except Exception as e:
        logger.error(f"[hook_analyzer] Failed to install apk... | Apk = {apk_path} | Error = {e}")
        return
    logger.info(f"[hook_analyzer] Granting permissions... | Apk = {apk_path} | Pkg = {pkg_name}")
    _, permissions = prepare_apk(apk_path)
    grant_permissions(permissions, pkg_name, adb_client, device)

    logger.info(f"[hook_analyzer] Starting proxy for network...") # or close proxy on your device
    proxy = subprocess.Popen(
        f"mitmdump",
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    logger.info(f"[hook_analyzer] Starting analyzing...")
    # hook recorders
    all_loaded_classes_file = os.path.join(hook_output_dir, f"{pkg_name}-{apk_name}-loaded_classes.json") # for debugging
    hooked_methods_file = os.path.join(hook_output_dir, f"{pkg_name}-{apk_name}-hooked_methods.json") # for debugging
    data_map_file = os.path.join(hook_output_dir, f"{pkg_name}-{apk_name}-data_map.json")

    # delete old files
    if os.path.exists(all_loaded_classes_file):
        os.remove(all_loaded_classes_file)
    if os.path.exists(hooked_methods_file):
        os.remove(hooked_methods_file)
    if os.path.exists(data_map_file):
        os.remove(data_map_file)

    logger.info(f"[hook_analyzer] Starting frida service...")
    recorder_files = [all_loaded_classes_file, hooked_methods_file, data_map_file]

    # start frida service (batch run to fit limited resources on testing device)
    batch_run_frida_service(apk_path, key_apis_path, logger_config, recorder_files, pkg_name, logger, frida_server_handler, frida_path)

    logger.info(f"[hook_analyzer] Terminate proxy...")
    proxy.terminate()
    time.sleep(5)  # waiting...

    logger.info(f"[hook_analyzer] Reformat output files...")
    try:
        # reformat files
        if os.path.exists(hooked_methods_file):
            with open(hooked_methods_file, "r+", encoding="utf-8") as f:
                content = f.read()
                f.seek(0)
                f.truncate()
                hooked_methods_json = json.loads("""{"hooked_methods": """ + f"[{content[:-2]}]" + "}")
                json.dump(hooked_methods_json, f, indent=4, ensure_ascii=False)
        if os.path.exists(data_map_file):
            with open(data_map_file, "r+", encoding="utf-8") as f:
                content = f.read()
                f.seek(0)
                f.truncate()
                data_map_json = json.loads("""{"data_map": """ + f"[{content[:-2]}]" + "}")
                reformatted_data_map = reformat_data_map(data_map_json["data_map"], magic_inference)
                json.dump({"data_map": reformatted_data_map}, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[hook_analyzer] Failed to reformat output files... | Error = {e}")


def hook_analyzer(logger, logger_config, apk_dir, frida_path="/data/local/tmp/fs16.1.5arm64"):
    logger.info(f"[hook_analyzer] Starting hook analyzer...")
    apks_info_file = os.path.join(apk_dir, "apks_info.json") # auto-generated file
    if not os.path.exists(apks_info_file):
        logger.error(f"[hook_analyzer] Apks info file not found. | File = {apks_info_file}")
        sys.exit(1)
    apks_info = open(apks_info_file, "r", encoding="utf-8")
    apks_info = json.load(apks_info)

    # filter out apks that have been analyzed
    exist_packages = [file.split("-")[0] for file in os.listdir(hook_output_dir) if file.endswith("data_map.json")]
    
    # init frida environment
    logger.info(f"[hook_analyzer] Executing adb forwards...")
    adb_forwards(device, logger)
    logger.info(f"[hook_analyzer] Starting frida server...")
    frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
    frida_server_handler.start()
    
    total_apks = len(apks_info)
    for idx, apk_path in enumerate(apks_info):
        try:
            logger.info(f"[hook_analyzer] [start] {idx+1}/{total_apks}: apk_path = {apk_path}")
            pkg_name, file_name = apks_info[apk_path]["pkg_name"], apks_info[apk_path]["file_name"]
            if pkg_name in exist_packages:
                continue
            key_apis_path = os.path.join(key_apis_output_dir, f"{pkg_name}-{file_name}-key-apis.json")
            dynamic_analyzer(
                apk_path,
                pkg_name,
                file_name,
                key_apis_path,
                WAIT_FOR_DATA_TRANSMISSION,
                adb_client,
                device,
                logger,
                logger_config,
                frida_server_handler,
                frida_path,
            )
            t2 = time.time()
            logger.info(f"[hook_analyzer] [end] {idx+1}/{total_apks}: apk_path = {apk_path}")
        except Exception as e:
            logger.error(f"[hook_analyzer] Hook analyzer failed, Apk = {apk_path}. | {e}")
            logger.error(f"[hook_analyzer] Lost apk: {apk_path}")
            logger.info(f"[hook_analyzer] Terminating frida server...")
            frida_server_handler.terminate()
            time.sleep(30)
            wake_up_device_if_shutdown(adb_client, device, frida_path)

            logger.info(f"[hook_analyzer] Executing adb forwards...")
            adb_forwards(device, logger)
            logger.info(f"[hook_analyzer] Restarting frida server...")
            frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
            frida_server_handler.start()
    frida_server_handler.terminate()
    logger.info(f"[hook_analyzer] Finished hooking analysis...")
