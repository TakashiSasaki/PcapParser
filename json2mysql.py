#!/usr/bin/python
from __future__ import print_function
import MySQLdb
import config
import json
import sys
from decimal import Decimal


def insert(conn, o):
  keys = ','.join(o.keys())

  for k,v in o.items():
    if isinstance(v, float):
      o[k] = Decimal(v)

  print(Decimal(o["time"]), type(o["time"]))
  s = "INSERT INTO %s.%s(%s) VALUES (%s)" % (config.DB, config.TABLE, keys, ','.join(["%s"]*len(o.values())))
  #print(s)
  #print(o.values())
  try:
    cursor = conn.cursor()
    cursor.execute(s, o.values())
    conn.commit()

  except MySQLdb.ProgrammingError as e:
    if e.args[0] == 1146:
      columns = []
      for k,v in o.items():
        if isinstance(v, bool):
          columns.append(k + " " + "BOOLEAN")
        elif isinstance(v, int):
          columns.append(k + " " + "BIGINT")
        elif isinstance(v, long):
          columns.append(k + " " + "BIGINT")
        elif isinstance(v, str):
          columns.append(k + " " + "VARCHAR(%s)" % config.VARCHAR_LENGTH) 
        elif isinstance(v, unicode):
          columns.append(k + " " + "VARCHAR(%s)" % config.VARCHAR_LENGTH) 
        elif isinstance(v, Decimal):
          columns.append(k + " " + "DECIMAL(%s,%s)" % config.DECIMAL_DIGIT)
        else:
          raise Exception(type(v))
      print(columns)
      sql = "CREATE TABLE %s (%s)" % (config.TABLE, ','.join(columns))
      print(sql)
      cursor = conn.cursor()
      cursor.execute(sql)
      insert(conn, o)
    else:
      raise e

  except MySQLdb.OperationalError as e:
    if e.args[0] == 1054:
      for k,v in o.items():
        cursor = conn.cursor()
        if isinstance(v, bool):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s BOOLEAN" % (config.TABLE, k))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        elif isinstance(v, int):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s BIGINT" % (config.TABLE, k))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        elif isinstance(v, long):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s BIGINT" % (config.TABLE, k))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        elif isinstance(v, str):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s VARCHAR(65535)" % (config.TABLE, k))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        elif isinstance(v, unicode):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s VARCHAR(65535)" % (config.TABLE, k))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        elif isinstance(v, Decimal):
          try: 
            cursor.execute("ALTER TABLE %s ADD COLUMN %s DECIMAL(%s,%s)" % (config.TABLE, k, config.DECIMAL_DIGIT[0], config.DECIMAL_DIGIT[1]))
            conn.commit()
          except MySQLdb.OperationalError as e2: 
            print(e2)
            pass
        else:
          raise Exception(type(v))
      insert(conn, o)          
    else:
      raise e

  except MySQLdb.IntegrityError as e:
    if e.args[0] == 1062:
      pass
    else:
      raise e


if __name__ == "__main__":
  conn = MySQLdb.connect(user=config.USER, db=config.DB)
  cursor = conn.cursor()
  sql = "show databases"
  cursor.execute(sql)
  for row in cursor.fetchall():
    print(row, file=sys.stderr)

  f = open(config.JSON_FILE)
  l = json.load(f)

  for o in l:
    insert(conn, o)

