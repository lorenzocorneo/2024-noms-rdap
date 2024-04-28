# From WHOIS to RDAP: Are IP Lookup Services Getting any Better?

This repository contains the code used for the evaluation, analysis and figures included in the paper: "From WHOIS to RDAP: Are IP Lookup Services Getting any Better?", which is part of the proceeding of IEEE NOMS 2024. To be noticed, the dataset is not provided and should be retrieved separately in order to run the analysis provided in the code.

**DISCLAIMER:** The code is best effort and not actively maintained. It was developed for the sole purpose to provide insights on IP lookup services that are included in the paper.

## How to run the code

First of all, install the required libraries listed in the file `requirements.txt` and create the folders `data` and `figures` to store the output of the code.

```sh
pip install -r requirements.txt
mkdir data figures
```

Second, change the paths in the file `utils.py` (lines 10 to 13) to point to your database(s) containing RDAP, or WHOIS, records. For the evaluation, a `sqlite3` database was used with a simple schema, e.g., two columns such as UUID and stored information; it is possible to see the queries to the various databases in the code. To be notice, the papers uses results only from RDAP, WHOIS, and headers databases (RPSL was not used).

```python
# Add here the paths to your database
rpsl_db_path    = ...
whois_db_path   = ...
rdap_db_path    = ...
headers_db_path = ...
```

Finally, all the RDAP-related plots included in the paper can be generated with the following command:

```sh
python rdapanalysis.py
```

## Optimization functions

The algorithms used in the paper can be found in the file `utils.py` under the functions `flatten_json`, `depth`, `find_redundant_values`, `redundancy_values`, `redundancy_values_bytes`, `rdap_compression`, and `rdap_entity_flattening`.

## Cite the paper
TODO: Add bibtex once provided
