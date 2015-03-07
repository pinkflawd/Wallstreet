'''
Created on 18.09.2013

@author: pinkflawd
'''

import logging.config
import os.path
import sqlite3

from Exceptions import DatabaseError
from ctypes.test.test_funcptr import lib


class SQLiteDB(object):
    
    '''
    SQLiteDB CLASS
    interaction with sqlite, waaaay slower than mssql but totally portable ^^
    '''

    try:
        logging.config.fileConfig(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..','..', 'conf', 'logger.conf'))
        log = logging.getLogger('SQLiteDB')
    except:
        # here could go some configuration of a default logger -- me too lazy
        print "Error, logger.conf not found or broken. Check on http://docs.python.org/2/howto/logging.html what to do."
        exit(1)

    
    def __init__(self):
        try:
            self.localdb = sqlite3.connect(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..','..', 'data', 'userland.sqlite'))
            # set row factory to Row type for accessing rows as dictionaries
            self.localdb.row_factory = sqlite3.Row
            self.localdb.text_factory = str
        except:
            raise DatabaseError, "Connection to DB cant be established."
        
    def __del__(self):
        try:
            self.localdb.close()
        except:
            pass
    
    ###########################
    # Base Operations         #
    ###########################

    def select(self, select_string):
        try: 
            cursor = self.localdb.cursor()
            cursor.execute(select_string)
        except:
            print select_string
            raise DatabaseError, "An Error occurred when executing a select."
        else:
            return cursor
        
    def insert(self, insert_string):
        try:
            cursor = self.localdb.cursor()
            cursor.execute(insert_string)
        except:
            print insert_string
            raise DatabaseError, "An Error occurred when executing an insert."
        else:
            self.localdb.commit()
            cursor.close()
            
    def delete(self, delete_string):
        try:
            cursor = self.localdb.cursor()
            cursor.execute(delete_string)
        except:
            print delete_string
            raise DatabaseError, "An Error occurred when executing a delete."
        else:
            self.localdb.commit()
            cursor.close()
            
    def update(self, update_string):
        try:
            cursor = self.localdb.cursor()
            cursor.execute(update_string)
        except:
            print update_string
            raise DatabaseError, "An Error occurred when executing an update."
        else:
            self.localdb.commit()
            cursor.close()
        
            

    ###########################
    # Extended Operations     #
    ###########################
            
    def select_id(self, select_string):
        cur = self.select(select_string)
        row = cur.fetchone()
        cur.close()
        if row:
            return row[0]
        else:
            return 0
        
    def select_funcid(self, libid, funcname, linecount):
        select_string = "select id from t_function where libid = %i and funcname = '%s' and linecount = %i" % (libid,funcname,linecount)
        id = self.select_id(select_string)
        return id
    
    def select_libid(self, filemd5, os):
        select_string = "select id from t_library where libmd5 = '%s' and os = '%s'" % (filemd5, os)
        id = self.select_id(select_string)
        return id

    def select_signatures(self):
        select_string = "select * from t_signature"
        res = self.select(select_string).fetchall()
        return res
    
    def select_suspicious(self):
        select_string = "select * from t_suspicious"
        res = self.select(select_string).fetchall()
        return res
            
    def flush_all(self):

        drop_string = """drop table if exists t_hit"""
        self.delete(drop_string)
                
        drop_string = """drop table if exists t_functioncall"""
        self.delete(drop_string)
        
        drop_string = """drop table if exists t_function"""
        self.delete(drop_string)
        
        drop_string = """drop table if exists t_library"""
        self.delete(drop_string)
        
        drop_string = """drop table if exists t_signature"""
        self.delete(drop_string)

        drop_string = """drop table if exists t_suspicious"""
        self.delete(drop_string)

        self.log.info("Database flushed")
 
    def flush_library(self, libid):
        delete_string = "delete from t_hit where libid = %i" % libid
        self.delete(delete_string)
        delete_string = "delete from t_functioncall where funcid in (select id from t_function where libid = %i)" % libid
        self.delete(delete_string)
        delete_string = "delete from t_function where libid = %i" % libid
        self.delete(delete_string)
        
    def flush_signature(self):
        delete_string = "delete from t_signature"
        self.delete(delete_string)
        
    def flush_suspicious(self):
        delete_string = "delete from t_suspicious"
        self.delete(delete_string)
        
    def insert_library(self, filemd5, filename, os):
        select_string = "select id from t_library where libmd5 = '%s' and os = '%s'" % (filemd5, os)
        lib = self.select(select_string).fetchall()
         
        if lib:
            self.log.info("Library with id %s in %s already exists" % (filemd5, os))
            return True
        
        else:
            insert_string = "insert into t_library (libmd5, libname, os) values ('%s','%s', '%s')" % (filemd5, filename, os)
            self.insert(insert_string)
            self.log.info("Library %s with id %s created" %(filename, filemd5))
            return False
            
                
                
    def insert_function(self, libid, funcname, linecount, suspicious):
        insert_string = "insert into t_function (libid, funcname, linecount, suspicious) values (%i, '%s', %i, %i)" % (libid, funcname, linecount, suspicious)
        self.insert(insert_string)
        
    def insert_functioncall(self, funcid, functioncall):
        insert_string = "insert into t_functioncall (funcid, functioncall) values (%i, '%s')" % (funcid, functioncall)
        self.insert(insert_string)
        
    def insert_signatures(self, signatures):
        self.flush_signature()
        for sig in signatures:
            insert_string = "insert into t_signature (sigpattern) values ('%s')" % sig
            self.insert(insert_string)
        self.log.info("Signatures inserted/updated")
    
    def insert_suspicious(self, suspicious):
        self.flush_suspicious()
        for sus in suspicious:
            insert_string = "insert into t_suspicious (suspiciouspattern) values ('%s')" % sus
            self.insert(insert_string)
        self.log.info("Suspicious patterns inserted/updated")
        
    def insert_hit(self, libid, funcid, sigpattern, line_offset):
        insert_string = "insert into t_hit (libid, funcid, sigpattern, line_offset) values (%i, %i, '%s', %i)" % (libid, funcid, sigpattern, line_offset)
        self.insert(insert_string)
    
    
    def set_linecount(self, linecount, funcid):
        update_string = "update t_function set linecount = %i where id = %i" % (linecount, funcid)
        self.update(update_string)
        
        
        
    ### DIFFING TASKS
    
    # gets libids for performing more Info tasks
    def select_libs_byname(self, libname):
        select_string = "select id, libname, os from t_library where libname like '%%%s%%'" % libname
        res = self.select(select_string)
        return res
    
    # returns a set of hitcounts, grouped by funcname and sigpattern for whole lib
    def select_diff_one(self, libid):
        select_string = """SELECT h.sigpattern, f.funcname, count(*) co
                FROM t_hit h, t_function f where h.funcid=f.id
                and h.libid=%s
                group by f.funcname, h.sigpattern
                order by f.funcname, h.sigpattern""" % libid
                
        cur_win7 = self.select(select_string)
        return cur_win7

    
    # returns a set of hitcounts, matching funcname and sigpattern of a line of a win7_diff set
    def select_diff_two(self, libid, pattern, funcname):
        select_string = """select count(*) co from t_hit h, t_function f where h.funcid=f.id
                         and h.libid=%s
                         and h.sigpattern='%s'
                         and f.funcname like '%%%s%%'
                         group by f.funcname, h.sigpattern""" % (libid,pattern,funcname)
        cur_win8 = self.select(select_string)
        return cur_win8
    
    #returns all hits found for a certain libid
    def select_lib_all(self, libid):
        select_string = """select l.libname, f.funcname, h.sigpattern, h.line_offset from t_hit h, t_function f, t_library l 
                           where h.libid = l.id and h.funcid = f.id and h.libid=%s""" % libid
        return self.select(select_string)
 
    #checks if function exists in library
    def select_function(self, funcname, libid):
        select_string = """select id from t_function where funcname like '%s%%' and libid=%s""" % (funcname, libid)
        cur = self.select(select_string)
        row = cur.fetchone()
        if row:
            return True
        else:
            return False     
        
        
    # get the os of a lib           
    def select_os(self,libid):
        select_string = "select os from t_library where id = %i" % libid
        return self.select(select_string)
    
    
    
    ### SUSPICIOUS TASKS (pun intended)
    
    # get all suspicious functions per library
    def select_suspicious_functions(self, libid):
        select_string = "select funcname from t_function where t_function.suspicious = 1 and t_function.libid = %i" % libid
        return self.select(select_string).fetchall()
    
    
    ### RATING TASKS
        
    # get all functions per os
    def select_functions_os(self, os):
        select_string = "select funcname, t_function.id, libname from t_function, t_library where t_function.libid = t_library.id and t_function.libid in (select id from t_library where os = '%s')" % os
        return self.select(select_string).fetchall()
    
    # get missing safeapi hits for rating
    def select_complementary_function(self, osB, libraryA, funcnameA):
        select_string = """select t_function.id from t_function, t_library where t_function.libid = t_library.id 
                        and t_function.libid in (select id from t_library where os = '%s') 
                        and funcname like '%s%%' and libname = '%s'""" % (osB, funcnameA, libraryA)
        return self.select(select_string).fetchall()
    
    def select_hits_per_function_pattern(self, funcid):
        select_string = "select count(*), sigpattern from t_hit where funcid = %i group by sigpattern" % funcid
        return self.select(select_string).fetchall();
    
    def select_complementary_hits(self, funcid, pattern):
        select_string = "select count(*) from t_hit where funcid = %i and sigpattern = '%s'" % (funcid, pattern)
        return self.select(select_string).fetchone()
    
    # check if one functionname is present in all os versions
    def select_number_function_per_os(self, funcname):
        select_string = "select count(*), os from t_function join t_library on t_function.libid=t_library.id where funcname like '%s%%' group by os" % funcname
        return self.select(select_string).fetchall()
    
    # get all safeapihits for a function id
    def select_safeapihits_per_function(self):
        select_string = """select funcid,count(*) from t_hit group by funcid""" 
        return self.select(select_string).fetchall()
    
    def update_rating(self, funcid, attribute, value):
        update_string = "update t_function set %s = %i where id = %i" % (attribute, value, funcid)
        self.update(update_string)
    
    
    ### TRAVERSAL
    
    def select_funcname(self, funcid):
        select_string = """select funcname, libid from t_function where id = %i""" % funcid
        return self.select(select_string).fetchall()
    
    def select_calling_functions(self, snippet_funcname, libid):
        select_string = """select funcid from t_functioncall, t_function where t_functioncall.funcid = t_function.id 
                        and  functioncall like '%s%%' and libid = %i group by funcid""" % (snippet_funcname, libid)
        return self.select(select_string).fetchall()
    
    ### OTHER
    
    def select_libid_all(self):
        select_string = "select id, libname, os from t_library"
        return self.select(select_string).fetchall()
    
    def select_os_all(self):
        select_string = "select distinct os from t_library"
        return self.select(select_string).fetchall()
        
    ###########################
    # Scheme Re-Creation      #
    # t_library               #
    # t_function              #
    # t_signature             #
    # t_hit                   # 
    ###########################
        
    def create_scheme(self):
        
        create_string = """CREATE TABLE t_library (
                           id integer primary key,
                           libmd5 blob,
                           libname text,
                           os text
                           )"""
        self.insert(create_string)

        create_string = """create table t_function (
                        id integer primary key,
                        libid integer not null,
                        funcname text,
                        linecount integer,
                        suspicious integer default 0,
                        exploitables integer default 0,
                        newness integer default 0,
                        safeapismissing integer default 0,
                        safeapihits integer default 0,
                        sanitychecks integer default 0,
                        foreign key(libid) references t_library(id)
                        )"""
        self.insert(create_string)
               
        create_string = """create table t_functioncall (
                        id integer primary key,
                        funcid integer not null,
                        functioncall text,
                        foreign key(funcid) references t_function(id)
                        )"""
        self.insert(create_string)
        
        create_string = """create table t_signature (
                        sigpattern text primary key,
                        mapping text
                        )"""
        self.insert(create_string)
        
        create_string = """ create table t_suspicious (
                        suspiciouspattern text primary key
                        )"""
        self.insert(create_string)
       
        create_string = """create table t_hit (
                        id integer primary key,
                        libid integer not null,
                        funcid integer not null,
                        sigpattern text not null,
                        line_offset integer,
                        foreign key(libid) references t_library(id),
                        foreign key(funcid) references t_function(id),
                        foreign key(sigpattern) references t_signature(sigpattern)
                        )"""
        
        self.insert(create_string)
        
        self.log.info("Database recreated")
        

