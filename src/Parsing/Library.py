'''
Created on 05.09.2013

@author: pinkflawd
'''

import hashlib
import logging.config
import os
import re

from Exceptions import ParameterError, FileError
import Function


class Library(object):
    
    '''
    LIBRARY CLASS
    represents a library in the database
    '''
    
    try:
        logging.config.fileConfig(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..','..', 'conf', 'logger.conf'))
        log = logging.getLogger('Library')
    except:
        # here could go some configuration of a default logger -- me too lazy
        print "Error, logger.conf not found or broken. Check on http://docs.python.org/2/howto/logging.html what to do."
        exit(1)


    def __init__(self, path, os):
        
        if len(path) < 300:
            sanipath = re.sub('\'','', path,0)
            self.path = sanipath
        else:
            raise ParameterError, "Path Parameter too long! max. 299" 
            
        if len(os) < 6:
            self.os = os
        else:
            raise ParameterError, "OS Parameter too long! Expects Win7 or Win8 or Win10, max. 5"
        
        try:
            self.file = open(self.path)
        except:
            raise FileError, "Cant open given file for parsing! Unknown Error."
            
        else:    
            self.log.info("parsing %s for %s" % (self.path, self.os))
            
            data = self.file.read()
            self.filemd5 = hashlib.md5(data).hexdigest()
            self.file.close()
            
            import Database.SQLiteDB
            self.db = Database.SQLiteDB.SQLiteDB()
            self.backend = "SQLITE"
                
            self.existant = self.db.insert_library(self.filemd5,self.path,self.os)
            self.id = self.db.select_libid(self.filemd5)
           
        
    def parse_cfile(self):
        
        # Regexes to scan for whatever needed
        f_off = re.compile('^[^\/|\s|#].+(stdcall|cdecl|thiscall|fastcall|userpurge|usercall).+[^\)].*$')   
        semico = re.compile('[;|=]')
        comment = re.compile('^[\/\/|#]')
        brackon = re.compile('{')
        brackoff = re.compile('}')
        call = re.compile(r'([A-Za-z0-9_]+\(.*\))')
        operand = ['if(','while(','for(','switch(','return(','LODWORD(','LOBYTE(','LOWORD(','HIWORD(','HIBYTE(','WORD(','BYTE2(','BYTE4(','ifelse(','else(']
        
        linecount = 0
        brackflag = 0
        suspiciousflag = 0
        function = None
        
        try:
            self.file = open(self.path)
        except:
            raise FileError, "Can't open file to parse. At parse_cfile."
        
        else:
            
            self.log.info("Parsing...... pls wait")
            
            for line in self.file:
                
                if f_off.search(line) and not semico.search(line): ###### FIND FUNCTIONS WITHOUT CALLING CONV.
                    
                    # suspicious pattern in functionname scanning HERE
                    suspiciouspatterns = self.db.select_suspicious()
                    
                    for sus in suspiciouspatterns:
                        susscan = re.compile(sus[0])
                        if susscan.search(line):
                            suspiciousflag = 1 # DO SOMETHING ABOUT THIS add to function table or something
                        
                    # create new function (object) with linecount 0
                    if function is not None:
                        self.log.error("Something wrong with the brackets? %s" % function.funcname)
                        print brackflag
                              
                    function = Function.Function(self.id, line.rstrip(), 0, suspiciousflag)

                    linecount = 0
                    brackflag = 0
                    suspiciousflag = 0
                    
                elif function is not None and not comment.search(line):                      #inside a function and not a comment line
      
                    ### here: check if line worth scanning: enough characters to fit a signature :P
                    rline = line.replace(' ','')
                    
                    # cut off comments
                    blubb = rline.partition('//')
                    rline = blubb[0]
                    
                    # search for signatures
                    if (len(rline) > 11):
                        signatures = self.db.select_signatures()
                        
                        for sig in signatures:
                            sigscan = re.compile(sig[0])
                            
                            if sigscan.search(line):
                                #print sig[0]
                                
                                ### here: check for mapping, if exists, replace sig
                                if (sig[1] is not None):
                                    function.signature_found(function.libid,function.id,sig[1],linecount+1)
                                    #print "MAPPING found %s in %s" % (sig['mapping'], line.rstrip())
                                else:
                                    function.signature_found(function.libid,function.id,sig[0],linecount+1)
                    
                    # parsing for called functions within actual function
                    if (len(rline) > 5):
                        if (call.search(line)):
                            sani_line = re.sub('["\'\\\]', '', line)
                            
                            # cut out function signature from line
                            cut_fcalls = call.search(sani_line)
                            if cut_fcalls:
                                #print cut_fcalls.group()
                                if any (word in cut_fcalls.group() for word in operand):
                                    #print cut_fcalls.group()
                                    pass
                                else:
                                    function.add_functioncall(cut_fcalls.group())
                                 
                    if (brackon.search(rline)):
                        brackflag += 1

                    if (brackoff.search(rline)):
                        brackflag -= 1
                        if (brackflag == 0):
                            function.set_linecount(linecount+1)
                            function = None
                                                        
                    if function is not None:                  
                        # every line: count++
                        linecount = linecount+1
                    
                else:
                    pass
            
            if function is not None:
                self.log.error("Something wrong with the brackets? %s" % function.funcname)
            else:
                self.log.info("Success.")
            
            self.file.close()
 
        
    def flush_me(self):
        self.db.flush_library(self.id)
        self.log.info("Library %s with id %s flushed" % (self.path, self.filemd5))
        
