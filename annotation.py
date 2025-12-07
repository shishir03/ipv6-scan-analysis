import pyasn
asn_db = pyasn.pyasn('pfx2as_rounded.txt')

with open('ipv6_hitlist.txt') as f, open('ipv6_annotated.txt','w') as out:
    next(f)
    for ip in f:
        ip = ip.strip()
        # print(ip)
        res = asn_db.lookup(ip)
        if res:
            asn, prefix = res
            out.write(f"{ip},{asn},{prefix}\n")
