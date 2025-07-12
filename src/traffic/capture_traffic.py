import os
import time
import subprocess
import traceback
import frida
import json
from loguru import logger
from multiprocessing import Process, Event, Queue
from config import adb_client, device, traffic_output_dir, traffic_filtered_output_dir, WAIT_FOR_DATA_TRANSMISSION
from utils import (
    collect_apks,
    adb_forwards,
    apk_install,
    adb_uninstall,
    prepare_apk,
    grant_permissions,
    check_permission_full_screen_window,
    run_frida,
    check_device_connection,
    traffic_filter,
    wake_up_device_if_shutdown,
    filter_traffic_finished_apks,
)


def bypass_ssl_verify_service(package_name, logger_config, exit_event, comm_queue, time_out):
    with open("src/hookscript/bypass.js", encoding="utf-8") as f:
        src = f.read()
    bypass_ssl_logger = logger.bind(name=logger_config["bind_name"])
    bypass_ssl_logger_id = bypass_ssl_logger.add(
        logger_config["file_sink"],
        encoding="utf-8",
        enqueue=True,
        filter=lambda msg: msg["extra"].get("name") == logger_config["bind_name"],
    )

    try:
        remote_device = frida.get_remote_device()
        try:
            pid = remote_device.spawn([package_name])
        except frida.TimedOutError:
            permission_page = check_permission_full_screen_window(adb_client, device)
            if permission_page:
                bypass_ssl_logger.info(f"[capture traffic] [bypass ssl] frida time out because of permission page, skip.")
                return
            else:
                bypass_ssl_logger.error(f"[capture traffic] [bypass ssl] frida time out.")
                raise frida.TimedOutError("unexpectedly timed out while waiting for app to launch")
            
        session = remote_device.attach(pid)
        script = session.create_script(src)
        script.on("message", lambda message, data: bypass_ssl_logger.info(f"[capture traffic] [bypass ssl] Frida message: {message}, data: {data}"))
        script.load()
        remote_device.resume(pid)

        # wait for termination
        start_time = time.time()
        finish_time = time.time()
        while not exit_event.is_set() and finish_time - start_time < time_out:
            time.sleep(1)
            finish_time = time.time()
        else:
            logger.remove(bypass_ssl_logger_id)
            session.detach()

        # handle timeout
        if finish_time - start_time >= time_out:
            bypass_ssl_logger.error("[capture traffic] Frida service timeout...")
            comm_queue.put(TimeoutError("Frida service timeout..."))
    except Exception as e:
        bypass_ssl_logger.error(f"[capture traffic] Failed to start ssl bypassing instrumentation... | Error = {e}")
        comm_queue.put(e)


def capture_single_apk_traffic(apk_path, adb_client, device, timer, frida_path, logger, logger_config):
    # androguard preprocessing
    pkg_name = ""
    pkg_name, permissions = prepare_apk(apk_path)
    logger.info(f"[capture traffic] [verify] Apk = {apk_path}")

    # install apk
    apk_install(apk_path, device, frida_path)
    logger.info(f"[capture traffic] [install] Pkg = {pkg_name} | Apk = {apk_path}")

    # grant permissions
    grant_permissions(permissions, pkg_name, adb_client, device)
    logger.info(f"[capture traffic] [grant permissions] Pkg = {pkg_name} | Apk = {apk_path}")

    # delete duplicate traffic files
    apk_name = os.path.basename(apk_path)[:os.path.basename(apk_path).rfind(".")]
    simple_traffic_file = os.path.join(traffic_output_dir, f"{pkg_name}-{apk_name}-simple.json")
    raw_traffic_file = os.path.join(traffic_output_dir, f"{pkg_name}-{apk_name}-raw.bin")
    if os.path.exists(simple_traffic_file):
        os.remove(simple_traffic_file)  # delete old simple traffic file
    if os.path.exists(raw_traffic_file):
        os.remove(raw_traffic_file)  # delete old raw traffic file

    # capture traffic using mitmproxy
    logger.info(f"[capture traffic] Traffic capturing start... | Pkg = {pkg_name} | Apk = {apk_path}")
    proxy = subprocess.Popen(
        f"mitmdump -s src/traffic/httpdump.py --set pkg_name={pkg_name} --set apk_name={apk_name}",
        shell=False,  # make sure this can be terminated
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    # try to launch app and bypass ssl
    logger.info(f"[capture traffic] Launching app & bypass ssl... | Pkg = {pkg_name} | Apk = {apk_path}")
    bypass_ssl_exit_event = Event()
    bypass_ssl_comm_queue = Queue()
    bypass_ssl_proc = Process(target=bypass_ssl_verify_service, args=(pkg_name, logger_config, bypass_ssl_exit_event, bypass_ssl_comm_queue, timer * 2))
    bypass_ssl_proc.start()

    # wait for data transmission
    logger.info(f"[capture traffic] Wait for data transmission... | Pkg = {pkg_name} | Apk = {apk_path}")
    time.sleep(int(timer))

    # check if frida service has errors
    if not bypass_ssl_comm_queue.empty():
        err = bypass_ssl_comm_queue.get()
        logger.error(f"[capture traffic] Bypass ssl frida service error: {err}")
        adb_uninstall(pkg_name, device)
        proxy.kill()
        raise RuntimeError(f"[capture traffic] Bypass ssl frida service error: {err}")

    # uninstall app
    logger.info(f"[capture traffic] Uninstalling apk from device... | Pkg = {pkg_name} | Apk = {apk_path}")
    adb_uninstall(pkg_name, device)

    # terminate frida service
    logger.info(f"[capture traffic] Terminating bypass ssl frida service... | Pkg = {pkg_name} | Apk = {apk_path}")
    bypass_ssl_exit_event.set()
    bypass_ssl_proc.join()

    # close mitmproxy
    logger.info(f"[capture traffic] Terminating proxy... | Pkg = {pkg_name} | Apk = {apk_path}")
    proxy.kill()
    time.sleep(5)  # waiting...

    logger.info(f"[capture traffic] Reformat output traffic file... | Pkg = {pkg_name} | {apk_path}")
    try:
        if os.path.exists(simple_traffic_file):
            with open(simple_traffic_file, "r+", encoding="utf-8") as f:
                content = f.read()
                f.seek(0)
                f.truncate()
                traffic_json = json.loads("""{"traffic": """ + f"[{content[:-2]}]" + "}")
                json.dump(traffic_json, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[capture traffic] Failed to reformat output traffic file... | Error = {e}")


def filter_unrelated_traffic(traffic_blacklist_path, logger, end_with="simple.json"):
    traffic_filter(traffic_blacklist_path, traffic_output_dir, traffic_filtered_output_dir, logger, end_with)


def capture_traffic(logger, logger_config, root="apks", frida_path="/data/local/tmp/fs16.1.5arm64", traffic_blacklist_path="src/system_traffic_blacklist.txt"):
    logger.info("[capture traffic] Start running...")
    apks = []  # parse all apks in root dirs and subdirs
    if os.path.isdir(root) and device:
        apks = collect_apks(root, logger)
        logger.info(f"[capture traffic] Total apks: {len(apks)} -> {apks}")
        finished_apks = filter_traffic_finished_apks(traffic_output_dir)

        # init frida environment
        logger.info(f"[capture traffic] Executing adb forwards...")
        adb_forwards(device, logger)
        logger.info(f"[capture traffic] Starting frida server...")
        frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
        frida_server_handler.start()

        # capture traffic for each apk
        for idx, apk_path in enumerate(apks):
            if os.path.basename(apk_path)[:os.path.basename(apk_path).rfind(".")] in finished_apks:
                logger.info(f"[capture traffic] Skip finished apk: {apk_path}")
                continue
            count = f"{idx + 1}/{len(apks)}"
            try:
                check_device_connection(logger)
                logger.info(f"[capture traffic] [start] {count}: apk_path = {apk_path}")
                capture_single_apk_traffic(apk_path, adb_client, device, WAIT_FOR_DATA_TRANSMISSION, frida_path, logger, logger_config)
            except Exception as e:
                logger.error(f"[capture traffic] Parse apk failed, apk: {apk_path} | {e}")
                logger.error(f"[capture traffic] Lost apk: {apk_path}")
                logger.info(f"[capture traffic] Terminating frida server...")
                frida_server_handler.terminate()
                time.sleep(30)
                wake_up_device_if_shutdown(adb_client, device, frida_path)

                logger.info(f"[capture traffic] Executing adb forwards...")
                adb_forwards(device, logger)
                logger.info(f"[capture traffic] Restarting frida server...")
                frida_server_handler = Process(target=run_frida, args=(adb_client, device, frida_path))
                frida_server_handler.start()
        frida_server_handler.terminate()
    logger.info("[capture traffic] Start filtering unrelated traffic...")
    filter_unrelated_traffic(traffic_blacklist_path, logger)
    logger.info("[capture traffic] Finish filtering unrelated traffic.")
    logger.info("[capture traffic] Finish running.")
