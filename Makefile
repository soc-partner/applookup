all: effective-tld ndpi

effective-tld:
	python3 ./aux/effective-tld-parser.py

ndpi:
	bash ./aux/ndpi.parser.bash

purge:
	rm -rf domains.in nets.in effective-tld.zeek
