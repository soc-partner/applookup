#!/bin/bash

rm -rf nDPI
git clone https://github.com/ntop/nDPI.git

grep " 0x" nDPI/src/lib/ndpi_content_match.c.inc | grep -v '0x0, 0, 0' > ip.raw
for filename in nDPI/src/lib/inc_generated/ndpi_*inc; do
    if [ $filename == "nDPI/src/lib/inc_generated/ndpi_icloud_private_relay_match.c.inc" ]; then
        continue
    fi
    grep " 0x" $filename | grep -v '0x0, 0, 0' >> ip.raw
done

echo "#fields	ip	name" > nets.in
sed -e 's=^.*{ 0x[0-9A-Za-z]* /. \([^ /|^*]*\).*, *\([0-9][0-9]*\) *, NDPI_PROTOCOL_\([A-Za-z0-9_]*\) .*=\1/\2	\3=' < ip.raw | sort | uniq >> nets.in

egrep -o '{ ".*", +".*"' nDPI/src/lib/ndpi_content_match.c.inc > domain.raw
echo "#fields	domain	name" > domains.in
sed -r 's/^\s+"//; s/",\s+"/\t/; s/".+?$//; s/^[^\.]/\^&/; s/\t/\$\t/; s/\.\$/\./; s/\./\\\./g; s/^[^\t]+/\/&\//' domain.raw >> domains.in

rm -rf nDPI 
rm ip.raw domain.raw
