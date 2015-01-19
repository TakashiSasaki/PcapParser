%.tcpdump : %.pcap
	tcpdump -tt -r $<  > $@

clean:
	rm *.json

all:	dump_20150115174406.pcap	
	./pcap-parser.py 

