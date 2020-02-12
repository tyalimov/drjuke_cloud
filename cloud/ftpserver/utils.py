import hashlib
import sys
import os 
import json

import ML.FileClassify

BUF_SIZE = 65536

g_Hashes              = ""
g_ResourcesDirectory  = "ftp_data\\av_distributive"
g_MalwareDirectory    = "ftp_data\\malware"
g_ResourceParameters  = dict()

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

def GetMalwarePath():
    return os.path.join(GetMyPath(), g_ResourcesDirectory)

def GetResourceFile(filename):
    return os.path.join(GetResourcesPath(), filename)

def GetHashes():
    
    files_list = []
    resources_dir = GetResourcesPath()
    for (root, dirnames, filenames) in os.walk(resources_dir):
        for filename in filenames:
            rel_dir = os.path.relpath(root, resources_dir)
            rel_file = os.path.join(rel_dir, filename)
            files_list.append(rel_file)
            #print(rel_file)

    for filename in files_list:
        g_ResourceParameters[filename] = (Sha512(GetResourceFile(filename)), os.stat(GetResourceFile(filename)).st_size)

    return json.dumps(g_ResourceParameters).encode('utf-8')

def AiScan(filename):
    target = os.path.join(GetMalwarePath(), filename)
    classifier = ML.FileClassify.FileClassify()
    result = classifier.isMalware(target)

    if result:
        return "{ \"infected\" : true }"
    else:
        return "{ \"infected\" : false }"