import json
import sqlite3
import timeit
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from typing import List

import matplotlib.patches as patches
import matplotlib.pyplot as plt
import numpy as np
from funcy import merge_with
from matplotlib.ticker import MaxNLocator

from utils import (cdf, depth, find_redundant_values, flatten_json, hcdf,
                   rdap_compression, rdap_db_path, rdap_entity_flattening,
                   redundancy_values, redundancy_values_bytes)


@dataclass(frozen=True)
class RDAPRecord:
    raw: str
    ip: str
    uuid: int
    rtt: int = 0

    def __hash__(self):
        return hash((self.raw))

    @lru_cache(32)
    def _url2rir(self, rir) -> str:
        translate = {
            "whois.arin.net": "ARIN",
            "whois.ripe.net": "RIPE",
            "whois.lacnic.net": "LACNIC",
            "whois.apnic.net": "APNIC",
            "whois.afrinic.net": "AFRINIC",
            "whois.nic.br": "LACNIC",
        }
        if translate[rir] != "":
            return translate[rir]
        return ""

    @lru_cache(32)
    def to_dict(self) -> dict:
        try:
            return json.loads(self.raw)
        except:
            return {}

    @lru_cache(32)
    def getRIR(self) -> str:
        if self.to_dict().get("port43"):
            return self._url2rir(self.to_dict()["port43"])
        return ""

    @lru_cache(32)
    def isNotFound(self) -> bool:
        return (
            True
            if self.to_dict().get("errorCode") and self.to_dict()["errorCode"] == 404
            else False
        )

    @lru_cache(32)
    def isError(self) -> bool:
        return (
            True
            if len(self.raw) == 0
            or "Time-out" in self.raw
            or self.to_dict().get("errorCode")
            else False
        )

    @lru_cache(32)
    def recordSize(self) -> int:
        """Returns the size in bytes of a utf-8 formatted string"""
        return len(self.raw.encode("utf-8"))

def load_dataset() -> List[RDAPRecord]:
    ret = []
    connection = sqlite3.connect(rdap_db_path)
    for row in connection.execute(
        "SELECT ip, record, r.id FROM whois_records AS r INNER JOIN nodes AS n WHERE r.node_id = n.id;"
    ):
        ret.append(RDAPRecord(row[1], row[0], row[2]))
    return ret


def load_dataset_latency() -> List[RDAPRecord]:
    ret = []
    connection = sqlite3.connect(rdap_db_path)
    for row in connection.execute(
        """SELECT ip, record, r.id, rtt
            FROM whois_records AS r INNER JOIN nodes AS n
            WHERE r.node_id = n.id AND rtt IS NOT NULL;"""
    ):
        ret.append(RDAPRecord(row[1], row[0], row[2], row[3]))
    return ret


def load_dataset_redirects() -> List[int]:
    ret = []
    connection = sqlite3.connect(rdap_db_path)
    for row in connection.execute(
        """SELECT http_redirects
            FROM whois_records
            WHERE http_redirects IS NOT NULL;"""
    ):
        ret.append(row[0])
    return ret


def load_dataset_dict() -> dict:
    ret = {}
    connection = sqlite3.connect(rdap_db_path)
    for row in connection.execute(
        "SELECT ip, record, r.id FROM whois_records AS r INNER JOIN nodes AS n WHERE r.node_id = n.id;"
    ):
        record = RDAPRecord(row[1], row[0], row[2])
        ret[record.ip] = record

    return {k: v for k, v in ret.items() if not v.isError()}


def merge_count_keys(xs: List[dict]) -> List:
    return sorted(
        [(k, v) for k, v in merge_with(sum, *xs).items()],
        key=lambda x: x[1],
        reverse=True,
    )


def set_box_color(bp, color):
    plt.setp(bp["boxes"], color=color)
    plt.setp(bp["whiskers"], color=color)
    plt.setp(bp["caps"], color=color)
    plt.setp(bp["medians"], color=color)


def plot_keys(ds_rdap):
    # There are 6 records that are a copy of WHOIS records and must be
    # deducted from the total
    num_records = len(ds_rdap) - 6
    keys = merge_count_keys([x.countKeys() for x in ds_rdap])
    keys = [(k, v) for k, v in keys if v > 6]
    rdap_bars = keys
    width = 0.5

    print(num_records, rdap_bars)

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 4.7))

    ax.barh([], [])
    ax.barh(
        range(len(rdap_bars)),
        [x / (num_records - 6) * 100 for _, x in rdap_bars],
        width,
    )
    ax.set_yticks(
        list(range(len(rdap_bars))),
        [k[:15] + "..." if len(k) > 15 else k for k, _ in rdap_bars],
    )
    plt.yticks(fontsize="x-small")
    plt.ylabel("Key")
    plt.xlabel("Occurrences [%]")
    plt.tight_layout()
    plt.savefig("./figures/bar-rdap-keys.pdf")
    plt.show()


def plot_redundancy(records: List[RDAPRecord]):
    xs = [redundancy_values(r.to_dict()) for r in records]
    zs = [redundancy_values_bytes(r.to_dict()) for r in records]

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 2.7))

    plt.plot(sorted(xs), cdf(xs), label="Redundancy [values]")
    plt.plot(sorted(zs), cdf(zs), label="Redundancy [bytes]")

    plt.xlabel("Redundancy [%]")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-rdap-redundancy.pdf")
    plt.show()


def plot_redundancy_type(records: List[RDAPRecord]):
    ds = defaultdict(int)
    for r in records:
        rs = find_redundant_values(r.to_dict())
        for k, v in rs.items():
            if type(k) == int:
                continue
            if k[:6] in ["https:", "whois."]:
                ds["URL"] += v
            elif k in [
                "application/json+rdap",
                "application/xml",
                "text/html",
            ]:
                ds["link type"] += v
            elif k in ["vcard", "work", "tel", "email", "text"]:
                ds["vcard"] += v
            elif k in [
                "active",
                "locked",
                "transfer prohibited",
                "inactive",
                "proxy",
                "removed",
                "obscured",
                "private",
                "validated",
            ]:
                ds["status"] += v
            elif k in [
                "registration",
                "last changed",
                "transfer",
                "expiration",
            ]:
                ds["event"] += v
            else:
                ds["others"] += v
    print(ds)
    tot = sum(ds.values())
    print({k: v / tot * 100 for k, v in ds.items()})


def plot_heatmap_key_depth(records: List[RDAPRecord]):
    es = defaultdict(list)
    ds = defaultdict(list)
    original = []
    optimized = []

    # Calculate depth for all the keys of the records
    for k, v in [(k, v) for r in records for k, v in r.to_dict().items()]:
        # OBS: Apparently there are few RDAP records that return whois records
        if k in ["objects", "version", "terms-and-conditions", "parameters"]:
            continue
        ds[k].append(depth(v))

    for i in range(0, 5):
        row = []
        for k, v in ds.items():
            # 4 is the maximum depth detected, change this manuall if
            # higher values appear.
            row.append(len([x for x in v if x == i]) / len(v))
        original.append(row)

    print(original)

    for k, v in [
        (k, v) for r in records for k, v in rdap_entity_flattening(r.to_dict()).items()
    ]:
        # OBS: Apparently there are few RDAP records that have
        # `objects` from WHOIS records
        if k in ["objects", "version", "terms-and-conditions", "parameters"]:
            continue
        es[k].append(depth(v))

    # for k in ds.keys():
    for k in ["entities"]:
        row = []
        # 4 is the maximum depth detected, change this manuall if
        # higher values appear.
        for i in range(0, 5):
            row.append(len([x for x in es[k] if x == i]) / len(es[k]))
        optimized.append(row)

    entities_index = list(ds.keys()).index("entities") + 1

    for i, r in enumerate(original):
        r.insert(entities_index, optimized[0][i])

    fig, ax = plt.subplots(figsize=(5, 2.7))
    im = ax.imshow(original, cmap="binary", aspect="auto", origin="lower")

    ax.set_ylabel("Depth")
    ax.set_xlabel("RDAP top level objects")
    ticks = list(ds.keys())
    ticks.insert(ticks.index("entities") + 1, "entities (flat)")
    ax.set_xticks(
        range(0, len(ticks)),
        [d[:15] + "..." if len(d) > 16 else d for d in ticks],
        fontsize=8,
        rotation=45,
        ha="right",
    )
    ax.grid(False)
    ax.set_yticks(range(0, 5), labels=range(0, 5))
    cbar = ax.figure.colorbar(im, ax=ax)
    cbar.ax.set_ylabel("Density (%)", rotation=-90, va="bottom")

    # Create a Rectangle patch
    rect = patches.Rectangle(
        (9.2, 0),
        2.3,
        4.3,
        linewidth=2,
        linestyle=":",
        edgecolor="r",
        facecolor="none",
    )
    ax.add_patch(rect)

    fig.tight_layout()
    plt.savefig("./figures/heatmap-rdap-keys-depth.pdf")
    plt.show()


def plot_depth_by_key(records: List[RDAPRecord]):
    ds = defaultdict(list)
    es = defaultdict(list)
    for k, v in [
        (k, v)
        for r in records
        for k, v in r.to_dict().items()
        if not r.isError() and not r.isNotFound()
    ]:
        # OBS: Apparently there are few RDAP records that have
        # `objects` from WHOIS records
        if k == "objects":
            continue
        ds[k].append(depth(v) + 1)

    # OBS: After analysis, the depth of `entities` is 2 because the
    # vCard array has depth 2.
    for k, v in [
        (k, v)
        for r in records
        for k, v in rdap_entity_flattening(r.to_dict()).items()
        if not r.isError() and not r.isNotFound()
    ]:
        # OBS: Apparently there are few RDAP records that have
        # `objects` from WHOIS records
        if k == "objects":
            continue
        es[k].append(depth(v) + 1)

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 4.7))

    bpn = plt.boxplot(
        ds.values(),
        labels=[d[:20] for d in ds.keys()],
        vert=False,
        positions=[r * 2 - 0.4 for r in range(len(ds))],
    )
    bpo = plt.boxplot(
        es.values(),
        labels=[e[:20] for e in es.keys()],
        vert=False,
        positions=[r * 2 + 0.4 for r in range(len(es))],
    )

    set_box_color(bpo, "#D7191C")  # colors are from http://colorbrewer2.org/
    set_box_color(bpn, "#2C7BB6")

    plt.plot([], c="#D7191C", label="RDAP OPT")
    plt.plot([], c="#2C7BB6", label="RDAP")
    plt.legend()

    plt.xlabel("Object depth")
    plt.ylabel("RDAP top level objects")
    plt.yticks(range(0, len(ds) * 2, 2), ds.keys())
    plt.yticks(fontsize=8)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.tight_layout()
    plt.savefig("./figures/box-rdap-depth-by-key.pdf")
    plt.show()


def plot_entities_depth(records: List[RDAPRecord]):
    ds = defaultdict(list)
    es = defaultdict(list)

    for r in [
        r
        for r in records
        if not r.isError() and not r.isNotFound() and r.to_dict().get("entities")
    ]:

        for es in [e for e in r.to_dict().get("entities")]:
            for k, v in es.items():
                ds[k].append(depth(v) + 1)

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 4.7))

    plt.boxplot(ds.values(), labels=[d[:20] for d in ds.keys()], vert=False)

    plt.xlabel("Object depth")
    plt.ylabel("RDAP top level objects")
    plt.yticks(fontsize=8)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-rdap-redundancy.pdf")
    plt.show()


def plot_rirs_entities(records: List[RDAPRecord]):
    ds = defaultdict(list)

    for r in records:
        if r.getRIR():
            ds[r.getRIR()].append(depth(r.to_dict()["entities"]))

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 1.7))

    plt.boxplot(ds.values(), labels=[d for d in ds.keys()], vert=False)
    plt.xlabel("Entities object depth")
    plt.ylabel("RIR")
    plt.yticks(fontsize=8)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.tight_layout()
    plt.savefig("./figures/box-rdap-rir-entities-depth.pdf")
    plt.show()


def heatmap_rirs_entities(records: List[RDAPRecord]):
    ds = defaultdict(list)
    heatmap = []
    for r in records:
        if r.getRIR():
            ds[r.getRIR()].append(depth(r.to_dict()["entities"]))

    for k in ds.keys():
        row = []
        # 4 is the maximum depth detected, change this manuall if
        # higher values appear.
        for i in range(0, 5):
            row.append(len([x for x in ds[k] if x == i]) / len(ds[k]))
        heatmap.append(row)

    fig, ax = plt.subplots(figsize=(4.7, 1.9))

    im = ax.imshow(heatmap, cmap="binary", aspect="auto")

    ax.set_xticks(range(0, 5), labels=range(0, 5))
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_yticks(
        range(0, len(ds)),
        ds.keys(),
        fontsize=8,
    )

    # Create colorbar
    ax.grid(False)
    cbar = ax.figure.colorbar(im, ax=ax)
    cbar.ax.set_ylabel("Density (%)", rotation=-90, va="bottom")

    plt.xlabel("Depth of entities object")
    plt.ylabel("RIR")
    plt.yticks(fontsize=8)
    plt.tight_layout()
    plt.savefig("./figures/heatmap-rdap-rir-entities-depth.pdf")
    plt.show()


def plot_empty_keys(records: List[RDAPRecord]):
    ds = defaultdict(int)

    tot = len(records)
    for k, v in [(k, v) for r in records for k, v in r.to_dict().items()]:
        if v == []:
            ds[k] += 1

    plt.style.use("ggplot")
    fig, ax = plt.subplots(figsize=(4.7, 1.7))

    ax.barh([], [])
    ax.barh(range(len(ds)), [x / tot * 100 for x in ds.values()], 0.5)
    ax.set_yticks(list(range(len(ds))), [k for k in ds.keys()])

    plt.ylabel("Key")
    plt.xlabel("Occurrences [%]")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/bar-rdap-empty-keys.pdf")
    plt.show()


def parsing_time(records: List[RDAPRecord]):
    original = []
    optimized = []
    foo = []
    for r in records:
        start = timeit.default_timer()
        fl = flatten_json(r.to_dict())
        stop = timeit.default_timer()
        original.append((stop - start) * 1000)
        start = timeit.default_timer()
        for k, v in fl.items():
            if type(v) is list:
                for x in v:
                    foo.append(v)
        stop = timeit.default_timer()
        optimized.append((stop - start) * 1000)

    fig, ax = plt.subplots(figsize=(2.7, 2.7))

    xs, ys = hcdf(optimized)
    with open("./data/cdf-rdap-parsing-optimized.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="Optimized")
    xs, ys = hcdf(original)
    with open("./data/cdf-rdap-parsing-original.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]

    plt.plot(xs, ys, label="Original")
    plt.xlim([-0.1, 1.5])
    plt.xlabel("Parsing time (ms)")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-rdap-parsing.pdf")
    plt.show()

    fig, ax = plt.subplots(figsize=(2.7, 2.7))

    value = np.mean([y / x for x, y in zip(optimized, original)])
    plt.bar(0, 1, 0.5, label="OPTIMIZED")
    plt.bar(
        1,
        value,
        0.5,
        label="ORIGINAL",
    )

    print("Original: ", value)
    plt.xlabel("")
    plt.xticks([0, 1], ["Optimized", "Original"])
    plt.ylabel("Normalized parsing time")
    # plt.legend(loc=2)
    plt.tight_layout()
    plt.savefig("./figures/bar-rdap-parsing.pdf")
    plt.show()


def http_redirects(xs: List[int]):
    # There is a bogus value in the dataset
    xs = [x for x in xs if x < 100]
    fig, ax = plt.subplots(figsize=(2.7, 2.7))

    xs, ys = hcdf(xs)
    with open("./data/cdf-http-redirects.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]

    plt.plot(xs, ys, label="RDAP")

    plt.xlim([-0.1, max(xs) + 0.1])
    plt.ylim([-0.1, 1.1])
    plt.xlabel("RDAP HTTP redirects")
    plt.ylabel("ECDF")
    # plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-http-redirects.pdf")
    plt.show()


# Call this function in the main method to generate the figures in the paper that concerns RDAP
def generate_all_figs(records: List[RDAPRecord]):
    heatmap_rirs_entities(records)
    plot_heatmap_key_depth(records)
    parsing_time(records)


def main():
    # records = load_dataset_dict()
    records = [r for r in load_dataset() if not r.isError() and not r.isNotFound()]
    generate_all_figs(records)

records_size_appendix(
if __name__ == "__main__":
    main()
