import requests
import json
import ndjson
import csv
import io
import pyzipper
import os
import subprocess
import sys
import logging
from rich.logging import RichHandler
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler(f"./log/{datetime.now():%Y%m%d%H%M%S}.log")
file_handler.setFormatter(logging.Formatter("%(asctime)s@ %(name)s [%(levelname)s] %(funcName)s: %(message)s"))
file_handler.setLevel(logging.DEBUG)

console_handler = RichHandler(rich_tracebacks=True)
console_handler.setLevel(logging.INFO)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


def main():
    SAMPLES_DIRNAME = "samples"
    SAMPLES_TSVNAME = "samples.tsv"
    SAMPLES_JSONNAME = "samples.ndjson"
    try:
        mdlist = fetch_from_malware_bazaar()
        for data in mdlist:
            try:
                data.VT = fetch_from_virus_total(data)
                download_malware(SAMPLES_DIRNAME, data.sha256)
                data.DIE = detect_with_die(SAMPLES_DIRNAME, data.sha256)
                data.appendTSV(SAMPLES_TSVNAME)
                data.appendJSON(SAMPLES_JSONNAME)
                logger.info(data.toString())
            except Exception as e:
                tb = sys.exc_info()[2]
                logger.error(e.with_traceback(tb))
    except RuntimeError as e:
        tb = sys.exc_info()[2]
        logger.error(e.with_traceback(tb))


class MalwareData():
    def __init__(self, sha256, filetype, tags):
        self.sha256 = sha256
        self.filetype = filetype
        self.tags = tags
        self.VT = None
        self.DIE = None

    def toString(self):
        return f"{self.sha256=}\t{self.filetype=}\t{self.tags=}\t{self.VT=}\t{self.DIE=}"

    def appendTSV(self, filename):
        data = [
            self.sha256,
            self.tags,
            self.VT,
            self.DIE
        ]

        with open(filename, "a", newline="", encoding="UTF-8") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(data)

    def appendJSON(self, filename):
        data = {
            "sha256": self.sha256,
            "tags": self.tags,
            "VirusTotal": self.VT,
            "DIE": self.DIE
        }

        with open(filename, "a", encoding="UTF-8") as f:
            writer = ndjson.writer(f)
            writer.writerow(data)


def fetch_from_malware_bazaar():
    data = {
        "query": "get_recent",
        "selector": "time"
    }

    with requests.post("https://mb-api.abuse.ch/api/v1/", data=data) as response:
        if response.status_code != 200:
            raise RuntimeError(f"Malware Bazaar's get_recent API returned a status_code {response.status_code}.")

        j = json.loads(response.content)
        l = [MalwareData(d["sha256_hash"], d["file_type"], d["tags"]) for d in j["data"]]
        return list(filter(lambda x: x.filetype == "exe", l))


def fetch_from_virus_total(data):
    headers = {
        "x-apikey": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    }

    with requests.get(f"https://www.virustotal.com/api/v3/files/{data.sha256}", headers=headers) as response:
        if response.status_code != 200:
            if response.status_code == 404:
                logger.info(f"Virus Total's file API hasn't an information of {data.sha256}.")
            else:
                logger.info(f"Virus Total's files API returned a status code {response.status_code}.")
            return None

        j = json.loads(response.content)
        try:
            return j["data"]["attributes"]["packers"]
        except KeyError:
            logger.info("Virus Total's info hasn't any packer data.")
            return None


def download_malware(dirname, sha256):
    data = {
        "query": "get_file",
        "sha256_hash": sha256
    }

    with requests.post("https://mb-api.abuse.ch/api/v1/", data=data) as response:
        if response.status_code != 200:
            raise RuntimeError(f"Malware Bazaar's get_file API returned a status code {response.status_code}.")

        with (
            io.BytesIO(response.content) as raw_data,
            pyzipper.AESZipFile(raw_data) as zip
        ):
            filename = zip.namelist()[0]
            path = zip.extract(member=filename, path=f"./{dirname}/", pwd=b"infected")
            os.rename(path, f"./{dirname}/{sha256}")


def detect_with_die(dirname, sha256):
    path = f"./{dirname}/{sha256}"
    if not os.path.isfile(path):
        return None

    try:
        with subprocess.Popen(["diec", "-j", path], stdout=subprocess.PIPE) as proc:
            outs, _ = proc.communicate(timeout=10)
            data = json.loads(outs)
            for d in data["detects"][0]["values"]:
                if d["type"] == "Packer":
                    return d["string"]
    except Exception as e:
        tb = sys.exc_info()[2]
        logger.error(e.with_traceback(tb))

    return None


if __name__ == "__main__":
    main()
