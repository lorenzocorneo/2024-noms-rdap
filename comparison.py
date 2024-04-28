import json
from typing import List

import matplotlib.pyplot as plt
from funcy import count_reps
from matplotlib.ticker import MaxNLocator
from rdp import rdp

import rdapanalysis as rdap
import rpslanalysis as rpsl
import whoisanalysis as whois
from utils import (
    cdf,
    depth,
    hcdf,
    rdap_compression,
    redundancy_values,
    redundancy_values_bytes,
    utf8len,
)


def records_size(ds_rdap: List, ds_whois: List):
    fig, ax = plt.subplots(figsize=(3.7, 2.3))

    whois_rec = [x.recordSize() / 1000 for x in ds_whois]
    whois_rec_no_grs = [x.recordSizeNoGRS() / 1000 for x in ds_whois]
    rdap_rec = [x.recordSize() / 1000 for x in ds_rdap]

    rdap_comp = [
        utf8len(json.dumps(rdap_compression(x.to_dict()))) / 1000 for x in ds_rdap
    ]

    xs, ys = hcdf(rdap_rec)
    plt.plot(xs, ys, label="RDAP original")
    with open("./data/cdf-size-rdap-original.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    xs, ys = hcdf(rdap_comp)
    plt.plot(xs, ys, label="RDAP optimized")

    with open("./data/cdf-size-rdap-optimized.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]

    xs, ys = hcdf(whois_rec_no_grs)
    plt.plot(xs, ys, label="WHOIS (no GRS)")
    with open("./data/cdf-size-whois-no-grs.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]

    plt.xlim([0, 21])
    plt.xlabel("Size (KB)")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-size.pdf")


def records_size_appendix(ds_whois: List):
    fig, ax = plt.subplots(figsize=(3.7, 2.3))

    whois_rec = [x.recordSize() / 1000 for x in ds_whois]
    whois_rec_no_grs = [x.recordSizeNoGRS() / 1000 for x in ds_whois]

    xs, ys = hcdf(whois_rec)
    with open("./data/cdf-size-whois.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="GRS Approx.")

    xs, ys = hcdf(whois_rec_no_grs)
    with open("./data/cdf-size-whois-no-grs.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="NO GRS Approx.")

    plt.xlim([0, 21])
    plt.xlabel("Size (KB)")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-size-appendix.pdf")


def rirs(ds: List[rdap.RDAPRecord | whois.WHOISRecord]):
    ds_reps = count_reps(
        [
            x.getRIR()
            for x in ds
            if not x.isNotFound() and not x.isError() and x.getRIR()
        ]
    )
    total = sum(ds_reps.values())
    bars_perc = sorted(
        [(k, v / total * 100) for k, v in ds_reps.items()],
        key=lambda x: x[1],
        reverse=True,
    )
    bars = bars_perc
    print(bars_perc)
    fig, ax = plt.subplots(figsize=(3.7, 1.7))

    bs = ax.barh([x for x in range(len(bars))], [x for _, x in bars])

    for i, bar in enumerate(bs):
        width = bar.get_width() + 1
        label_y_pos = bar.get_y() + bar.get_height() / 2
        # *2 because the same amount was collected for rdap also
        ax.text(
            width,
            label_y_pos,
            s=f"{ds_reps[bars_perc[i][0]]*2//1000}k",
            va="center",
            fontsize=8,
        )

    ax.set_yticks(list(range(len(bars))), [k for k, _ in bars])
    ax.set_xlim([0, 51])
    plt.xlabel("Amount (%)")
    plt.grid(False)
    plt.tight_layout()
    plt.savefig("./figures/bar-rirs.pdf")
    plt.show()


def pair_dataset(ds_rdap: dict, ds_whois: dict) -> dict:
    ret = {}
    for ip, record in ds_rdap.items():
        if ds_whois.get(ip):
            ret[ip] = (record, ds_whois[ip])
    return ret


def redundancy(ds_rdap: List, ds_whois: List):
    rdap_v = [redundancy_values(r.to_dict()) for r in ds_rdap]
    rdap_b = [redundancy_values_bytes(r.to_dict()) for r in ds_rdap]

    rdap_opt_v = [redundancy_values(rdap_compression(r.to_dict())) for r in ds_rdap]
    rdap_opt_b = [
        redundancy_values_bytes(rdap_compression(r.to_dict())) for r in ds_rdap
    ]

    fig, ax = plt.subplots(figsize=(3.7, 2.3))

    xs, ys = hcdf(rdap_v)
    with open("./data/cdf-rdap-original-redundancy-value.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="Original (values)")
    xs, ys = hcdf(rdap_b)
    with open("./data/cdf-rdap-original-redundancy-byte.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="Original (bytes)")

    xs, ys = hcdf(rdap_opt_v)
    with open("./data/cdf-rdap-optimized-redundancy-value.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="Optimized (values)")
    xs, ys = hcdf(rdap_opt_b)
    with open("./data/cdf-rdap-optimized-redundancy-byte.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="Optimized (bytes)")

    plt.xlabel("Redundancy (%)")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-rdap-redundancy.pdf")


def depth_max(ds_rdap: List[rdap.RDAPRecord], ds_whois: List[whois.WHOISRecord]):
    rs = [depth(r.to_dict()) for r in ds_rdap]
    ws = [depth(r.to_dict()) for r in ds_whois]

    fig, ax = plt.subplots(figsize=(3.7, 1.7))

    xs, ys = hcdf(rs)
    plt.plot(xs, ys, label="RDAP")
    with open("./data/cdf-max-depth-rdap.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    xs, ys = hcdf(ws)
    plt.plot(xs, ys, label="WHOIS")
    with open("./data/cdf-max-depth-whois.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]

    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    plt.xlabel("Maximum depth")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-rdap-whois-max-depth.pdf")


def response_time():
    rs = [
        x.rtt
        for x in rdap.load_dataset_latency()
        if not x.isError() and not x.isNotFound()
    ]
    ws = [
        x.rtt
        for x in whois.load_dataset_latency()
        if not x.isError() and not x.isNotFound()
    ]

    fig, ax = plt.subplots(figsize=(2.7, 2.7))

    xs, ys = hcdf(rs)
    with open("./data/cdf-rdap-response-time.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="RDAP")

    xs, ys = hcdf(ws)
    with open("./data/cdf-whois-response-time.dat", "w") as f:
        f.write("x y\n")
        [f.write(f"{x} {y}\n") for x, y in zip(xs, ys)]
    plt.plot(xs, ys, label="WHOIS")

    plt.xscale("log")
    plt.xlabel("Response time (ms)")
    plt.ylabel("ECDF")
    plt.legend(loc="best")
    plt.tight_layout()
    plt.savefig("./figures/cdf-response-time.pdf")
    plt.show()


def generate_all_figs(ds_rdap, ds_whois):
    rirs(ds_rdap)
    depth_max(ds_rdap, ds_whois)
    redundancy(ds_rdap, ds_whois)
    records_size(ds_rdap, ds_whois)
    response_time()
    records_size_appendix(ds_whois)


def main():
    ds_rdap = [r for r in rdap.load_dataset() if not r.isError() and not r.isNotFound()]
    ds_whois = whois.load_dataset()
    generate_all_figs(ds_rdap, ds_whois)


if __name__ == "__main__":
    main()
