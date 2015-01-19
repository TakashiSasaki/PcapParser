#!/usr/bin/python
from __future__ import print_function
import re
import sys
import json
from decimal import Decimal

class DecimalEncoder(json.JSONEncoder):
  def default(self, o):
    if isinstance(o, Decimal): 
      return float(o) 
    return super(DecimalEncoder, self).default(o)

read_count = 0
a = []
for l in sys.stdin:
  r1 = re.compile("^([0-9:.]+) IP ([0-9a-zA-Z_.-]+) > ([0-9a-zA-Z_.-]+): Flags \[([.FSP]+)\], (.+)$")
  m1 = r1.search(l)
  read_count+=1
  if m1 is None: 
    print("malformed line at %s" % read_count, file=sys.stderr)
    print(l, file=sys.stderr)
    exit(-1)
  d = {}
  d["time"] = Decimal(m1.group(1))
  d["src"] = m1.group(2)
  d["dst"] = m1.group(3)
  d["flags"] = m1.group(4)

  r_host_port = re.compile("^(.+)[.]([0-9]+)$")
  d["src_host"] = r_host_port.search(d["src"]).group(1)
  d["src_port"] = int(r_host_port.search(d["src"]).group(2))
  d["dst_host"] = r_host_port.search(d["dst"]).group(1)
  d["dst_port"] = int(r_host_port.search(d["dst"]).group(2))

  r2 = re.compile("^seq ([0-9]+):([0-9]+), ack ([0-9]+), win ([0-9]+), options \[(.+)\], length ([0-9]+)$")
  m2 = r2.search(m1.group(5))
  if m2:
    d["seq_begin"] = int(m2.group(1))
    d["seq_end"] = int(m2.group(2))
    d["ack"] = int(m2.group(3))
    d["win"] = int(m2.group(4))
    d["options"] = m2.group(5)
    d["length"] = int(m2.group(6))

  r3 = re.compile("^ack ([0-9]+), win ([0-9]+), options \[(.+)\], length ([0-9]+)$")
  m3 = r3.search(m1.group(5))
  if m3:
    d["ack"] = int(m3.group(1))
    d["win"] = int(m3.group(2))
    d["options"] = m3.group(3)
    d["length"] = int(m3.group(4))

  r4 = re.compile("^seq ([0-9]+), win ([0-9]+), options \[(.+)\], length ([0-9]+)$")
  m4 = r4.search(m1.group(5))
  if m4:
    d["seq_begin"] = int(m4.group(1))
    d["win"] = int(m4.group(2))
    d["options"] = m4.group(3)
    d["length"] = int(m4.group(4))
 
  r8 = re.compile("^seq ([0-9]+), ack ([0-9]+), win ([0-9]+), options \[(.+)\], length ([0-9]+)$")
  m8 = r8.search(m1.group(5))
  if m8:
    d["seq_begin"] = int(m8.group(1))
    d["ack"] = int(m8.group(2))
    d["win"] = int(m8.group(3))
    d["options"] = m8.group(4)
    d["length"] = int(m8.group(5))

  if m2 is None and m3 is None and m4 is None and m8 is None:
    print("malformed payload at %s" % read_count, file=sys.stderr)
    print(m1.group(5), file=sys.stderr)

  if "options" in d:
    r5 = re.compile("^(?:nop,)*TS val ([0-9]+) ecr ([0-9]+)$")
    m5 = r5.search(d["options"])
    if m5:
      d["ts_val"] = int(m5.group(1))
      d["ts_ecr"] = int(m5.group(2))

    r6 = re.compile("^mss ([0-9]+),sackOK,TS val ([0-9]+) ecr ([0-9]+),(?:nop,)*wscale ([0-9]+)$")
    m6 = r6.search(d["options"]) 
    if m6:
      d["mss"] = int(m6.group(1))
      d["ts_val"] = int(m6.group(2))
      d["ts_ecr"] = int(m6.group(3))
      d["wscale"] = int(m6.group(4))
      d["sackok"] = True

    r7 = re.compile("^(?:nop,)*TS val ([0-9]+) ecr ([0-9]+),(?:nop,)*sack ([0-9]+) ((?:{[0-9]+:[0-9]+})+)$")
    m7 = r7.search(d["options"])
    if m7:
      d["ts_val"] = int(m7.group(1))
      d["ts_ecr"] = int(m7.group(2))
      d["sack_count"] = int(m7.group(3))
      d["sack_seq"] = m7.group(4)
 
    if m5 is None and m6 is None and m7 is None:
      print(d["options"])

  if "src" in d: del d["src"]
  if "dst" in d: del d["dst"]
  if "options" in d: del d["options"]
  a.append(d)

print(json.dumps(a, indent=2, cls=DecimalEncoder))

