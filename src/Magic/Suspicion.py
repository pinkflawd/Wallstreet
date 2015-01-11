'''
Created on 05.01.2015

@author: Marion
'''

class Suspicion(object):
    '''
    classdocs
    '''


    def __init__(self):
        import Database.SQLiteDB
        self.db = Database.SQLiteDB.SQLiteDB()
        
    def get_suspicous_all(self):
        libids = self.db.select_libid_all()
        
        for lib in libids:
            print lib[2], " - ", lib[1], ";"
            sus_functions = self.db.select_suspicious_functions(lib[0])
            for func in sus_functions:
                print ";", func[0]
                
    def get_suspicious_os(self, os):

        sus_functions_a = self.db.select_suspicious_functions_os(os)
        for func in sus_functions_a:
            snippet = func[0][:func[0].index('(')] + "("
            
            interesting = self.db.select_suspicious_function_peros(snippet)
            others = self.db.select_suspicious_functions_diff(snippet)
            
            if len(interesting) < 3: # or distinct os < 3
                print func[0], " present in:"
                for other in others:
                    print ";", other[0], ";", other[1]
            
        
