import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import List

import matplotlib.pyplot as plt
from funcy import flatten, merge_with, where

from utils import whois_db_path


@dataclass(frozen=True)
class WHOISRecord:
    raw: str
    ip: str
    rtt: int = 0

    def __hash__(self):
        return hash((self.raw))

    def _get_object_attributes(self, obj: dict) -> List[dict]:
        return obj["attributes"]["attribute"]

    @lru_cache(32)
    def _url2rir(self, rir: str) -> str:
        translate = {
            "arin-grs": "ARIN",
            "ripe": "RIPE",
            "lacnic-grs": "LACNIC",
            "apnic-grs": "APNIC",
            "afrinic-grs": "AFRINIC",
        }
        return translate[rir]

    def _countKeys(self, objs: List[dict], key: str) -> dict:
        """Returns a dict with the occurrences of the `key`"""
        ret = defaultdict(int)
        for obj in objs:
            ret[obj[key]] += 1
        return dict(ret)

    @lru_cache(32)
    def to_dict(self) -> dict:
        return json.loads(self.raw)

    @lru_cache(32)
    def get_objects(self) -> List[dict]:
        return self.to_dict()["objects"]["object"]

    @lru_cache(32)
    def get_objects_attributes(self) -> List[List[dict]]:
        return [
            [attrs for attrs in self._get_object_attributes(obj)]
            for obj in self.get_objects()
        ]

    @lru_cache(32)
    def get_objects_attributes_flat(self) -> List[List[dict]]:
        return list(flatten(self.get_objects_attributes()))

    @lru_cache(32)
    def isRIPE(self) -> bool:
        for attr in self.get_objects_attributes_flat():
            if attr["value"] and attr["value"] == "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK":
                return False
        return True

    @lru_cache(32)
    def isNotFound(self) -> bool:
        return len(self.removeNonRIPEObject().get_objects()) == 0

    # This is here just to make the type checker happy.
    @lru_cache(32)
    def isError(self) -> bool:
        return False

    @lru_cache(32)
    def removeNonRIPEObject(self):
        for i, obj in enumerate(self.get_objects()):
            for attr in self._get_object_attributes(obj):
                if (
                    attr["value"]
                    and attr["value"] == "NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK"
                ):
                    new_objects = [
                        d for j, d in enumerate(self.get_objects()) if j != i
                    ]
                    new_dict = {
                        k: v for k, v in self.to_dict().items() if k != "objects"
                    }
                    new_dict["objects"] = {}
                    new_dict["objects"]["object"] = new_objects
                    return WHOISRecord(json.dumps(new_dict), self.ip)
        return self

    @lru_cache(32)
    def getRIR(self) -> str:
        for obj in self.get_objects():
            if obj["source"]:
                return self._url2rir(obj["source"]["id"])
            return "UNKNOWN"

    @lru_cache(32)
    def getCountry(self) -> str:
        """Returns the country of the WHOIS record if present, otherwise `unknown`."""
        for attr in self.get_objects_attributes_flat():
            if attr["name"] and attr["name"] == "country":
                return attr["value"]
        return "UNKNOWN"

    @lru_cache(32)
    def getAttributesKeys(self) -> dict:
        return self._countKeys(self.get_objects_attributes_flat(), "name")

    @lru_cache(32)
    def getTypeKeys(self) -> dict:
        return self._countKeys(self.get_objects(), "type")

    @lru_cache(32)
    def recordSize(self) -> int:
        """Returns the size in bytes of a utf-8 formatted string"""
        return len(self.raw.encode("utf-8"))

    @lru_cache(32)
    def recordSizeNoGRS(self) -> int:
        """Returns the size in bytes of a utf-8 formatted string"""
        return len(self.removeNonRIPEObject().raw.encode("utf-8"))

    @lru_cache(32)
    def getIP(self) -> str:
        return self.ip

    @lru_cache(32)
    def getCreationDate(self) -> str:
        # Returns the creation date of the inetnum object, since the
        # route object usually comes afterwards.
        for a in self.get_objects_attributes_flat():
            if a.get("name") == "created":
                return a["value"]
        return ""

    @lru_cache(32)
    def getLastModifiedDate(self) -> str:
        # Returns the last modified date of the inetnum object, since
        # the route object usually comes afterwards.
        for a in self.get_objects_attributes_flat():
            if a.get("name") == "last-modified":
                return a["value"]
        return ""


def load_dataset() -> List[WHOISRecord]:
    ret = []
    connection = sqlite3.connect(whois_db_path)
    for row in connection.execute(
        "SELECT ip, record FROM whois_records AS r INNER JOIN nodes AS n WHERE r.node_id = n.id;"
    ):
        ret.append(WHOISRecord(row[1], row[0]))
    return ret


def load_dataset_latency() -> List[WHOISRecord]:
    ret = []
    connection = sqlite3.connect(whois_db_path)
    for row in connection.execute(
        """SELECT ip, record, rtt
           FROM whois_records AS r INNER JOIN nodes AS n
           WHERE r.node_id = n.id AND rtt IS NOT NULL;"""
    ):
        ret.append(WHOISRecord(row[1], row[0], row[2]))
    return ret


def load_dataset_dict() -> dict:
    ret = {}
    connection = sqlite3.connect(whois_db_path)
    for row in connection.execute(
        "SELECT ip, record FROM whois_records AS r INNER JOIN nodes AS n WHERE r.node_id = n.id;"
    ):
        record = WHOISRecord(row[1], row[0])
        ret[record.ip] = record
    return ret
