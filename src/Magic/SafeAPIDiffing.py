'''
Created on 13.10.2013

@author: Marion
'''

import re


class SafeAPIDiffing(object):
    '''
    INFO CLASS
    
    does all the info gathering out of the database
    stupid name i know
    '''


    def __init__(self):
        import Database.SQLiteDB
        self.db = Database.SQLiteDB.SQLiteDB()
        
        
    ###
    # search functions return cursors
    # diff functions create/open csv files
    # oh i like defining rules..
    ###
        
    def search_libs(self, libname):
        ids = self.db.select_libs_byname(libname) # libid, libname, os, filetype
        return ids
        
        #for item in ids:
        #    print "Library ID %s for %s with type %s and OS %s" % (item[0], item[1], item[3], item[2])
    
    
    def search_libs_diffing(self, libname):
        cur = self.db.select_libs_byname(libname)
        ids = cur.fetchall()    # without fetch the rowcount is always -1
        wids = []

        # works only for Win7/Win8 diffing !!
        if len(ids) == 2:
            if (ids[0][3].lower() == ids[1][3].lower()): #filetype
                if (ids[0][2] != ids[1][2]):
                    if (ids[0][2] == 'WIN7'): #os
                        wids.append(ids[0][0]) #id
                    elif (ids[1][2] == 'WIN7'): #os
                        wids.append(ids[1][0]) #id
                    else:
                        return -1
                    
                    if (ids[0][2] == 'WIN8'):
                        wids.append(ids[0][0])
                    elif (ids[1][2] == 'WIN8'):
                        wids.append(ids[1][0])
                    else:
                        return -1
                    
                    return wids
                else:
                    return -1
            else:
                return -1
        else:
            return -1


    def missing_safeapis_singlesided(self, osA, osB):
        
        # get all functions for OS A
        functions_osA = self.db.select_functions_os(osA) # funcname, id, libraryname
        
        # for any function in OS A get hitcount for func.osA and func.osB
        for function_osA in functions_osA:
            
            # get function name only, w.o. params
            snippet_funcosA = function_osA[0][:function_osA[0].index('(')] + "("
            function_osB = self.db.select_complementary_function(osB, function_osA[2], snippet_funcosA) # id
            if function_osB:
               
                # complementary functions: function_osA[1]  and  function_osB[0][0]
                
                ratingvalue = 0
                hits_funcA = self.db.select_hits_per_function_pattern(function_osA[1]) # count, pattern
                
                for hitA in hits_funcA:
                    hits_funcB = self.db.select_complementary_hits(function_osB[0][0], hitA[1]) # count
                    ratingvalue = ratingvalue + (hitA[0] - hits_funcB[0])
                
                if ratingvalue > 0:
                    self.db.update_rating(function_osB[0][0], 'safeapismissing', ratingvalue)
                    print "RATING %i / %i with %i" % (function_osA[1], function_osB[0][0], ratingvalue)
                
       

    # returns TEXT
    def diff_twosided(self, wAlib, wBlib):

        cur_one = self.db.select_diff_one(wBlib) # sigpattern,  funcname, count(*) co
        res = cur_one.fetchall()
         
        output = "Function_Name;Pattern;Win8_Hits;Win7_Hits\n"

        for item in res:
            fsplit = re.split('\(', item[1], 1, 0) #funcname
            
            cur_two = self.db.select_diff_two(wAlib,item[0],fsplit[0]) #sigpattern
            hitcount_two = cur_two.fetchone()
             
            if (hitcount_two):
                if item[2] != hitcount_two[0]: #count
                    output += "%s;%s;%s;%s\n" % (fsplit[0],item[0],item[2],hitcount_two[0]) # sigpattern, co, co

            elif (self.db.select_function(fsplit[0], wAlib)):
                output += "%s;%s;%s;0\n" % (fsplit[0],item[0],item[2]) # sigpattern, co

        output += "\nFunction_Name;Pattern;Win7_Hits;Win8_Hits\n"
        
        cur_one = self.db.select_diff_one(wAlib) # sigpattern,  funcname, count(*) co
        res = cur_one.fetchall()
         
        for item in res:
            fsplit = re.split('\(', item[1], 1, 0) # funcname
            
            cur_two = self.db.select_diff_two(wBlib,item[0],fsplit[0])
            hitcount_two = cur_two.fetchone()
             
            if (hitcount_two):
                if item[2] != hitcount_two[0]: # co
                    output += "%s;%s;%s;%s\n" % (fsplit[0],item[0],item[2],hitcount_two[0])

            elif (self.db.select_function(fsplit[0], wBlib)):
                output += "%s;%s;%s;0\n" % (fsplit[0],item[0],item[2])
                
        return output

    def library_info(self,libid):    
        cur_all = self.db.select_lib_all(libid) # libname, funcname, sigpattern, line_offset
        return cur_all

    
            
            