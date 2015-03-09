'''
Created on 05.01.2015

@author: Marion
'''

from Enums import OsVersion
from SafeAPIDiffing import SafeAPIDiffing
import os
import logging.config

class Rating(object):
    '''
    classdocs
    '''
    
    try:
        logging.config.fileConfig(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..','..', 'conf', 'logger.conf'))
        log = logging.getLogger('Rating')
    except:
        # here could go some configuration of a default logger -- me too lazy
        print "Error, logger.conf not found or broken. Check on http://docs.python.org/2/howto/logging.html what to do."
        exit(1)


    def __init__(self):
        import Database.SQLiteDB
        self.db = Database.SQLiteDB.SQLiteDB()
        
    def create_view(self):
        self.db.create_rating_view()
        
    def drop_view(self):
        self.db.drop_rating_view()
        
    def print_suspicous_all(self):
        libids = self.db.select_libid_all()
        
        for lib in libids:
            print lib[2], " - ", lib[1], ";"
            sus_functions = self.db.select_suspicious_functions(lib[0])
            for func in sus_functions:
                print ";", func[0]


    
    def rate_new_functions(self):
        
        final = []
        funcids_notnew = self.db.select_funcids_notnew()
        for tuple in funcids_notnew:
            final.append([int(tuple[0])])
            final.append([int(tuple[1])])
            final.append([int(tuple[2])])
        
        self.db.update_newness(final)

        self.log.info("DB updated with \"new\" rating")



    def rate_missing_safeapis(self):
        
        diffobj = SafeAPIDiffing()
        self.log.info("Safe API diffing for Win7/Win8")
        diffobj.missing_safeapis_singlesided(OsVersion.win7.value, OsVersion.win8.value)    # @UndefinedVariable
        diffobj.missing_safeapis_singlesided(OsVersion.win8.value, OsVersion.win7.value)    # @UndefinedVariable
        
        self.log.info("Safe API diffing for Win8/Win10")
        diffobj.missing_safeapis_singlesided(OsVersion.win8.value, OsVersion.win10.value)   # @UndefinedVariable
        diffobj.missing_safeapis_singlesided(OsVersion.win10.value, OsVersion.win8.value)   # @UndefinedVariable
        
    def rate_sanitychecks(self, funcid, sanitychecks):
        self.db.update_rating(funcid, 'sanitychecks', sanitychecks)
        
    def rate_exploitables(self, funcid, exploitables):
        self.db.update_rating(funcid, 'exploitables', exploitables)
        
    def rate_multiple(self, funcid, sanitychecks, exploitables, linecount):
        self.db.update_rating_multiple(funcid, sanitychecks, exploitables, linecount)
        
    def rate_safeapihits(self):
        allhits = self.db.select_safeapihits_per_function() # funcid, count
        for hit in allhits:
            self.db.update_rating(hit[0], 'safeapihits', hit[1])
            
    def traverse_calltree(self, funcid, level, looped):
        
        #list of traversed elements for avoiding loops
        looped.append(funcid)
        
        #fetching of called functions from current element
        function_name = self.db.select_funcname(funcid)
        snippet = function_name[0][0][:function_name[0][0].index('(')] + "("
        calling_functions = self.db.select_calling_functions(snippet, function_name[0][1])
        
        #print calling_functions
        indent = level * '-'
        print indent + " > " + str(funcid) + ": " + function_name[0][0]
        level = level + 1
        if calling_functions:
            for call in calling_functions:
                if call[0] not in looped:
                    self.traverse_calltree(call[0], level, looped)
            level = level - 1
            
    def get_functioncalls(self, funcid):
        functioncalls = self.db.select_functioncalls(funcid)
        for it in functioncalls:
            print it[2]
        
        