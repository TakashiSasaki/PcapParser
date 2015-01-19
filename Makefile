.PHONY: all clean

%.tcpdump : %.pcap
	tcpdump -tt -r $<  > $@

%.json : %.tcpdump
	./pcap-parser.py <$< >$@

clean:
	rm -f *.json *.tcpdump

all:	dump_20150115174406.json

