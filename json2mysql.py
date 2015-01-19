#!/usr/bin/python
import MySQLdb
import config

if __name__ == "__main__":
    connector = MySQLdb.connect(db=config.DB)
    cursor = connector.cursor()
    sql = "show databases"
    cursor.execute(sql)
    for row in cursor.fetchall():
        print(row)
 
  
