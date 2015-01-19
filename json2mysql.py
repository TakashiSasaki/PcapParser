#!/usr/bin/python
from __future__ import print_function
import MySQLdb
import config
import json
import sys

if __name__ == "__main__":
    connector = MySQLdb.connect(db=config.DB)
    cursor = connector.cursor()
    sql = "show databases"
    cursor.execute(sql)
    for row in cursor.fetchall():
        print(row, file=sys.stderr)
 
  
