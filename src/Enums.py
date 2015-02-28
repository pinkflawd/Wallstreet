'''
Created on 05.01.2015

@author: Marion
'''

from enum import Enum

class OsVersion(Enum):
    win7 = 'WIN7'
    win8 = 'WIN8'
    win10 = 'WIN10'
    version_count = 3
    
class Exploitables(Enum):
    load = 'LOAD'
    convert = 'CONVERT'
    create = 'CREATE'
    read = 'READ'
    decode = 'DECODE'
    save = 'SAVE'
    append = 'APPEND'
    copy = 'COPY'
    open = 'OPEN'
    alloc = 'ALLOC'
    move = 'MOVE'
    write = 'WRITE'
    memset = 'MEMSET'