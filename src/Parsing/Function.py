'''
Created on 12.09.2013

@author: pinkflawd
'''

import re

from Exceptions import ParameterError


class Function(object):
    '''
    FUNCTION CLASS
    represents the functions of a library in the database
    '''


    def __init__(self, libid, funcname, linecount, suspicious):
        
        #if u wish so, check libid if integer. but basically, not necessary     
        self.libid = libid
        
        if len(funcname) < 2000:
            sanifname = re.sub('\'','', funcname,0)
            sanifname = re.sub('^.+?(stdcall|cdecl|thiscall|fastcall|userpurge|usercall) ','',sanifname,1)
            self.funcname = sanifname
        else:
            raise ParameterError, "A funcname for function object is too long, max 1999 chars."
        
        if linecount < 2147483647: 
            self.linecount = linecount
        else:
            raise ParameterError, "Linecount exceeds int range - weiiird should never happen."
        
        if suspicious < 2 and suspicious >= 0:
            self.suspicious = suspicious
        else:
            raise ParameterError, "Suspicious value should be 1 or 0"
        
        import Database.SQLiteDB
        self.db = Database.SQLiteDB.SQLiteDB()
                
        self.db.insert_function(self.libid,self.funcname,self.linecount, self.suspicious)
        self.id = self.db.select_funcid(self.libid,self.funcname,self.linecount)
        
        
    def set_linecount(self,linecount):
        self.db.set_linecount(linecount, self.id)
    
    def signature_found(self, libid, funcid, sigpattern, line_offset):
        self.db.insert_hit(libid, funcid, sigpattern, line_offset)

    def add_functioncall(self, functioncall):
        self.db.insert_functioncall(self.id, functioncall)