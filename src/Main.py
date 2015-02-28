'''
Created on 05.09.2013

@author: pinkflawd
'''

import logging.config
from optparse import OptionParser
import os
import re
import sys
import traceback

import Magic.SafeAPIDiffing
import Magic.Rating
import Parsing.Library
from Enums import OsVersion


def main():
    
    '''
    MAIN CLASS
    command line option parsing
    exception catching
    '''
    
    try:
        logging.config.fileConfig(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'conf', 'logger.conf'))
        log = logging.getLogger('Main')
    except:
        # here could go some configuration of a default logger -- me too lazy
        # additionally one could add a cmdline option for loggint to a file instead of stdout -- me too lazy
        print "Error, logger.conf not found or broken. Check on http://docs.python.org/2/howto/logging.html what to do."
        exit(1)
    
    parser = OptionParser()
       
    ### Parsing
    parser.add_option("-d", "--dirparse", dest="directory", help="The directory which contains files for ONE os! Needs OS option.")
    parser.add_option("-n", "--no-flush", action="store_true", dest="noflush", help="Continue parsing without flushing existing function info - mb the app crashed before..")
    parser.add_option("-p", "--parse", dest="filename", help="The file to parse, needs the OS option")
    parser.add_option("-o", "--os", dest="os", help="OS the Library belongs to, Win7 or Win8")
    
    ### Maintenance
    parser.add_option("-f", "--flushall", action="store_true", dest="flush", help="Flush the Database Scheme")
    parser.add_option("-c", "--create-scheme", action="store_true", dest="createall", help="(Re)Create Database Scheme (same as flushall option)")
    parser.add_option("-u", "--update-sigs", action="store_true", dest="updatesigs", help="Flushes the signature table and re-reads the signatures.conf for update")
        
    ### Magic
    parser.add_option("-s", "--search_libs", dest="libname", help="Provide a library name (without .dll ending!!) to be searched in the DB, gives you the IDs you need for diffing!")
    parser.add_option("-a", "--lib_all_info", dest="lib_allinfo", help="Takes one libid as argument and prints all hit information in csv format")
    parser.add_option("-i", "--diff", action="store_true", dest="diff", help="Magic of two libraries, needs arguments lib1 and lib2, lib1 should be win7 as difflib, lib2 for win8 as baselib")
    parser.add_option("-1", "--lib_1", dest="lib_one", help="Difflib for diffing - Win7 goes here")
    parser.add_option("-2", "--lib_2", dest="lib_two", help="Baselib for diffing - Win8 goes here")
    parser.add_option("-e", "--diff_byname", dest="diffbyname", help="Diff two libs by name, two-sided, provide a libname like advapi32.c. CAUTION: Tool aborts when more than 2 libs are matched and DOES NOT VERIFY if the two difflibs belong together.")
    
    ### Rating
    parser.add_option("-x", "--suspicious_all", action="store_true", dest="suspicious_all", help="Gets all suspicious functions per library and prints them to CSV in data directory")
    parser.add_option("-r", "--rating", action="store_true", dest="rating", help="Does the rating magic and puts it into the DB")
    parser.add_option("-t", "--tree", dest="treetraversal", help="Provide a function ID for traversal of call tree")
    #parser.add_option("")
    
    (options, args) = parser.parse_args()
    

    import Database.SQLiteDB
    db = Database.SQLiteDB.SQLiteDB()

    ### OPTION parse ###
 
    if (options.filename is not None or options.directory is not None) and options.os is not None:
        
        try:
            
            lib_files = []
            
            if options.directory is not None:
                lib_files = [os.path.join(options.directory, f) for f in os.listdir(options.directory) if os.path.isfile(os.path.join(options.directory,f))]
            else:
                lib_files.append(options.filename)
                
            for lib_file in lib_files:        
                lib = Parsing.Library.Library(lib_file, options.os)
                
                # if lib exists - flush functions
                # if lib exists and no-flush active - continue
                if (lib.existant == True and options.noflush is None) or lib.existant == False:
                    lib.flush_me()
                    lib.parse_cfile()
                    
                    log.info("Finished Parsing")
                else:
                    log.info("Nothing to parse here, continue.")

        except:
            type, value, tb = sys.exc_info()
            log.error("Something went wrong when parsing a library: %s" % (sys.exc_info()[1]))
            traceback.print_exception(type, value, tb, limit=10, file=sys.stdout)
            log.error("If MSSQL, are the access credentials right? Did you set the right permissions on the DB? Did you perform a create_all on mssql or sqlite?")
        
        
    ### OPTION recreate or flush incomplete ###
    
    elif (options.flush == True or options.createall == True) and options.updatesigs is None:
        log.error("Options flushall and create-scheme need option --update-sigs or -u !!")
        
        
    ### OPTION recreate, flush or updatesigs ### 
        
    elif options.updatesigs == True:
        
        try:
            
            if options.flush == True or options.createall == True:
                db.flush_all()
                db.create_scheme()
                
            signatures = []
            suspicious = []
            
            try:
                sigfile = open(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'conf', 'signatures.conf'))
                suspiciousfile = open(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', 'conf', 'suspicious.conf'))
                
            except:
                log.error("Something went wrong when reading signature file.")
            else:  
                for line in sigfile:
                    #sanitizing the signatures
                    sig = re.sub('\'','', line.rstrip(),0)
                    signatures.append(sig)
                db.insert_signatures(signatures)
                sigfile.close()
                
                for line in suspiciousfile:
                    #sanitizing the suspicious patterns
                    sus = re.sub('\'','', line.rstrip(),0)
                    suspicious.append(sus)
                db.insert_suspicious(suspicious)
                suspiciousfile.close()
            
        except:
            log.error("Something went wrong when updating the signatures in DB.")

    ### OPTION search_libs gets you the lib IDs to a given libname ###
    
    elif options.libname is not None:
        # sanitizing
        sanilibname = re.sub('\'','', options.libname,0)
        info = Magic.SafeAPIDiffing.SafeAPIDiffing()
        cursor = info.search_libs(sanilibname)
        for item in cursor:
            print "Library ID %s for %s with OS %s" % (item[0], item[1], item[2])
    
    
    ### SUSPICOUS STUFF
    
    # Print all suspicious functions to commandline, format csv conform
    elif options.suspicious_all is not None:
        mysuspicion = Magic.Rating.Rating()
        mysuspicion.print_suspicous_all()
                
    # Search for added suspicious functions from Win10 downwards
    elif options.rating is not None:
        # get suspicious functions per OS
        mysuspicion = Magic.Rating.Rating()
        mysuspicion.rate_new_functions()
        mysuspicion.rate_missing_safeapis()



    # Call tree traversal!!
    
    
    
    
    
    
    
    
    
    
    ### OPTION lib_allinfo prints all hit information of one library, given the libid
    
    elif options.lib_allinfo is not None:
        try:
            libid = int(options.lib_allinfo)
        except ValueError:
            log.error("Libid has to be numeric!")
        else:
            info = Magic.SafeAPIDiffing.SafeAPIDiffing()
            cursor = info.library_info(libid)
            
            print "Libname;Functionname;Sigpattern;Line_Offset"
            for item in cursor:
                print "%s;%s;%s;%s" % (item[0],item[1],item[2],item[3]) 
    
    ### OPTION diff puts out csv content on the commandline or into a pipe, containing hitcounts of a win7 lib compared with a win8 lib ###
    
    elif options.diff == True:
        
        if options.lib_one is not None or options.lib_two is not None:
            
            try:
                w7lib = int(options.lib_one)
                w8lib = int(options.lib_two)
            except ValueError:
                log.error("Libids have to be numeric!")
            else:
                info = Magic.SafeAPIDiffing.SafeAPIDiffing()
                output = info.diff_twosided(w7lib, w8lib)
                print output
                
        else:
            log.error("The Diff Option needs two valid library IDs, get them using the search_libs option, providing a library name!")
        
    ### OPTION diff_byname
    
    elif options.diffbyname is not None:
        sanilibname = re.sub('\'','', options.diffbyname,0)
        info = Magic.SafeAPIDiffing.SafeAPIDiffing()
        ids = info.search_libs_diffing(sanilibname)
        if (ids != -1):
            #info.diff_libs(ids[0],ids[1])   # 0.. Win7, 1.. Win8
            output = info.diff_twosided(ids[0],ids[1])
            print output
        else:
            log.error("Something went wrong when choosing libs, maybe more than 2 matches or two libs with the same OS? Check with search_libs option!")
    
    
    
    else:
        log.error("Wrong Arguments - type -h or --help for Info")
        
if __name__ == '__main__':
    main()
    