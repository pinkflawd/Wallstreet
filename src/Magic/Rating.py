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
        
    def print_suspicous_all(self):
        libids = self.db.select_libid_all()
        
        for lib in libids:
            print lib[2], " - ", lib[1], ";"
            sus_functions = self.db.select_suspicious_functions(lib[0])
            for func in sus_functions:
                print ";", func[0]
    
    # returns functions per given OS which are not present in all three OS versions
    
    def get_new_per_os(self, os):

        to_flag = []

        functions_os1 = self.db.select_functions_os(os)
        for func_os1 in functions_os1:
            snippet_funcos1 = func_os1[0][:func_os1[0].index('(')] + "("
            
            interesting = self.db.select_number_function_per_os(snippet_funcos1) # ret count, os for this specific snippet
            if len(interesting) < OsVersion.version_count.value: # or distinct os < 3 @UndefinedVariable
                to_flag.append(func_os1[1]) # return function ids
            
        return to_flag
    
    def rate_new_functions(self):
        
        self.log.info("Get new functions Win7")
        flagged = self.get_new_per_os(OsVersion.win7.value)  # @UndefinedVariable
        self.log.info("Get new functions Win7")
        flagged = flagged + (self.get_new_per_os(OsVersion.win8.value)) # @UndefinedVariable
        self.log.info("Get new functions Win7")
        flagged = flagged + (self.get_new_per_os(OsVersion.win10.value))    # @UndefinedVariable
        
        for flag in flagged:
            self.db.update_rating(flag, 'newness', 1)
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
            
        