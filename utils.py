import json
from collections import defaultdict
from typing import List, Tuple

import numpy as np
from funcy import count_reps
from rdp import rdp

# Add here the paths to your database
rpsl_db_path = "/home/lc/go/src/intermezo/rpsl.db"
whois_db_path = "/home/lc/go/src/intermezo/whois.db"
rdap_db_path = "/home/lc/go/src/intermezo/rdap.db"
headers_db_path = "/home/lc/go/src/intermezo/rdap-header.db"


def countKeys(objs: List[dict], key: str) -> dict:
    """Returns a dict with the occurrences of the `key`"""
    ret = defaultdict(int)
    for obj in objs:
        ret[obj[key]] += 1
    return dict(ret)


def cdf(xs: List[float]) -> List[float]:
    """Calculate CDF values"""
    return 1.0 * np.arange(len(xs)) / (len(xs) - 1)


def hcdf_old(xs: List[float], bins=1000, startfromzero=True) -> Tuple[List[float], List[float]]:
    """Calculate CDF with histogram. Use this for big datasets as it compresses the CDF."""
    hist, edges = np.histogram(xs, bins=bins, density=True)
    # plot the data as a step plot.  note that edges has an extra right edge.
    xs, ys = edges[:-1], np.cumsum(hist * np.diff(edges))
    # The EDCF should start from zero. Revert this setting
    if startfromzero and ys[0] > 0:
        ys[0] = 0.0
    return xs, ys

def hcdf(xs: List[float], epsilon=0.01) -> Tuple[List[float], List[float]]:
    """Calculate CDF with Ramer-Douglas-Peucker algorithm. Use this for big datasets as it reduces the number of data points."""
    rdp_cdf = rdp([[x, y] for x, y in zip(sorted(xs), cdf(xs))], epsilon=epsilon)
    return  [x for x, _ in rdp_cdf], [y for _, y in rdp_cdf]

def utf8len(j: str) -> int:
    """Returns the size in bytes of a utf-8 formatted string"""
    return len(j.encode("utf-8"))


def flatten_json(y, key_sep="."):
    """Flattens a JSON object. Used for analyzing keys and values of
    JSON objects"""
    out = {}

    def flatten_obj(x, name=""):
        if type(x) is dict:
            for a in x:
                flatten_obj(x[a], name + str(a) + key_sep)
        elif type(x) is list:
            i = 0
            for a in x:
                flatten_obj(a, name + str(i))
                i += 1
        else:
            out[name[:-1]] = x

    flatten_obj(y)
    return out


def depth(j: dict) -> int:
    return max(
        [len(k.split(".")) - 1 for k in flatten_json(j).keys()], default=0
    )


def find_redundant_values(j: dict, min_val: int = 1) -> dict:
    return {
        k: v
        for k, v in count_reps(flatten_json(j).values()).items()
        if v > min_val
    }


def redundancy_values(j: dict) -> float:
    """Calculates the percentage of redundancy of occurrences of values
    of a JSON object"""
    rs = find_redundant_values(j)
    tot = sum(count_reps(flatten_json(j).values()).values())
    return sum(
        {k: (v - 1) / tot * 100 for k, v in rs.items() if v - 1 > 0}.values()
    )


def redundancy_values_bytes(j: dict) -> float:
    """Calculates the percentage of redundancy of the values of a JSON object
    based on byte length"""
    rs = find_redundant_values(j)
    length = utf8len(json.dumps(j))
    return sum(
        {
            k: utf8len(str(k)) * (v - 1) / length * 100
            for k, v in rs.items()
            if v - 1 > 0
        }.values()
    )


def rdap_compression(j: dict) -> list | dict | str:
    ret = {}
    rs = find_redundant_values(j, 5)
    new_part = {
        v: k for k, v in zip([f"x{i}" for i in range(len(rs))], rs.keys())
    }

    def walk(node, key) -> list | dict | str:
        if type(node) is dict:
            return {k: walk(v, k) for k, v in node.items()}
        elif type(node) is list:
            return [walk(x, key) for x in node]
        else:
            return node if node not in new_part.keys() else new_part[node]

    ret: dict | list | str = walk(j, "")
    if isinstance(ret, dict):
        ret["r"] = new_part
    return ret


def rdap_entity_flattening(j: dict) -> dict:
    ret: List[dict] = []

    def flatten_entities(source: list, output: List[dict]) -> List[dict]:

        for e in source:
            ret.append({k: v for k, v in e.items() if k != "entities"})
            if e.get("entities"):
                flatten_entities(e["entities"], ret)
        return ret

    j["entities"] = flatten_entities(j.get("entities", []), ret)
    return j
