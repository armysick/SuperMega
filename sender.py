import requests as req
import logging
import brotli
import time

from config import config


logger = logging.getLogger("Sender")


def scannerDetectsBytes(data: bytes, filename: str, useBrotli=True, verify=False, no_exec=False):
    if config.get("avred_server") == "":
        logger.error("No AVRed server configured, aborting")
        return
    params = { 'filename': filename, 'brotli': useBrotli, 'verify': verify, 'no_exec' : no_exec}
    
    if useBrotli:
        scanData = brotli.compress(data)
    else:
        scanData = data

    timeStart = time.time()
    logger.info("Send to exec/exe: {}".format(params))
    res = req.post("{}/exec/exe".format(config.get("avred_server")), params=params, data=scanData, timeout=10)
    jsonRes = res.json()
    scanTime = round(time.time() - timeStart, 3)
    logger.info("Response: {}s: {}".format(scanTime, jsonRes))
    

    # basically internal server error, e.g. AMSI not working
    if res.status_code != 200:
        logger.error("Error Code {}: {}".format(res.status_code, res.text))
        raise Exception("Server error, aborting")
    
    return jsonRes
