import hashlib
import sys
import os 
import json

BUF_SIZE = 65536

g_Hashes = ""
g_ResourcesDirectory = "resources"
g_ResourceParameters = dict()

def Sha512(filename):
    sha512 = hashlib.sha512()
    with open(filename, 'rb') as target_file:
        while True:
            data = target_file.read(BUF_SIZE)
            if not data:
                break
            sha512.update(data)
    
    return sha512.hexdigest()

def GetMyPath():
    return os.path.dirname(os.path.realpath(__file__))

def GetResourcesPath():
    return os.path.join(GetMyPath(), g_ResourcesDirectory)

def GetResourceFile(filename):
    return os.path.join(GetResourcesPath(), filename)

def GetHashes():
    for (dirpath, dirnames, filenames) in os.walk(GetResourcesPath()):
        for filename in filenames:
            g_ResourceParameters[filename] = (Sha512(GetResourceFile(filename)), os.stat(GetResourceFile(filename)).st_size)
        break

    return json.dumps(g_ResourceParameters).encode('utf-8')