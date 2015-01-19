%.tcpdump : %.pcap
	tcpdump -tt -r $<  > $@

%.json : %.tcpdump
	./pcap-parser.py <$< >$@

clean:
	rm *.json

all:	dump_20150115174406.pcap	
	./pcap-parser.py 

