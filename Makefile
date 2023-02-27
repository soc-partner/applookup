all: effective-tld ndpi

effective-tld:
	python3 ./aux/effective-tld-parser.py

ndpi:
	bash ./aux/ndpi.parser.bash
