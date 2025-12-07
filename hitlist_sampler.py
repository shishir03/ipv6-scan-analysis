import csv
from collections import defaultdict

asn_counts = defaultdict(int)
prefix_counts = defaultdict(int)
total = 0

with open("ipv6_annotated.txt") as f:
    reader = csv.reader(f)
    for ip, asn, prefix in reader:
        asn_counts[asn] += 1
        prefix_counts[(asn, prefix)] += 1
        total += 1

print("Total rows:", total)

N = 400_000
asn_quota = {}

for asn, count in asn_counts.items():
    q = int(N * count / total)
    asn_quota[asn] = max(q, 1)  # ensure at least one per ASN

prefix_quota = {}

for (asn, prefix), count in prefix_counts.items():
    q = int(asn_quota[asn] * count / asn_counts[asn])
    prefix_quota[(asn, prefix)] = max(q, 1)

import random

output = open("all_ipsx2", "w")
used = defaultdict(int)

with open("ipv6_annotated.txt") as f:
    reader = csv.reader(f)
    for ip, asn, prefix in reader:
        key = (asn, prefix)
        if used[key] < prefix_quota[key]:
            # Bernoulli acceptance, only if we still have quota left
            remaining_needed = prefix_quota[key] - used[key]
            # Accept this line with probability proportional to remaining quota
            # and remaining population
            p = remaining_needed / prefix_counts[key]
            if random.random() < p:
                output.write(ip + "\n")
                used[key] += 1

output.close()
