#!/bin/bash

# Remove the nDPI directory if it exists and clone the nDPI repository from GitHub
rm -rf nDPI
git clone https://github.com/ntop/nDPI.git

# Search for subnets in the nDPI source file and write them to a file
grep " 0x" nDPI/src/lib/ndpi_content_match.c.inc | grep -v '0x0, 0, 0' > ip.raw
for filename in nDPI/src/lib/inc_generated/ndpi_*inc; do
    if [ $filename == "nDPI/src/lib/inc_generated/ndpi_icloud_private_relay_match.c.inc" ]; then # Ignore this one
        continue
    fi
    grep " 0x" $filename | grep -v '0x0, 0, 0' >> ip.raw
done

# Format the sunets as Zeek-compatible source file and write them to a file
echo "#fields	ip	name" > nets.in
sed -e 's=^.*{ 0x[0-9A-Za-z]* /. \([^ /|^*]*\).*, *\([0-9][0-9]*\) *, NDPI_PROTOCOL_\([A-Za-z0-9_]*\) .*=\1/\2	\3=' < ip.raw | sort | uniq >> nets.in

# Search for domain names in the nDPI source file and write them to a file
egrep -o '{ ".*", +".*"' nDPI/src/lib/ndpi_content_match.c.inc > domain.raw

# Format the domain names as Zeek-compatible regular expressions and write them to a file
echo "#fields	domain	name" > domains.in
sed -r 's/^\s+"//; s/",\s+"/\t/; s/".+?$//; s/^[^\.]/\^&/; s/\t/\$\t/; s/\.\$/\./; s/\./\\\./g; s/^[^\t]+/\/&\//' domain.raw >> domains.in

# Remove the nDPI directory and the temporary raw files
rm -rf nDPI 
rm ip.raw domain.raw
