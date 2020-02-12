import pefile
import math
import hashlib

class PropertiesPE():

    def __init__(self):
        pass

    def get_md5(self, filename):
        with open(filename, 'rb') as f:
            m = hashlib.md5()
            while True:
                data = f.read(8192)
                if not data:
                    break
                m.update(data)
        
        return m.hexdigest()

    def calculate_entropy(self, data):
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x)))/len(data)
            if p_x > 0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    def is_PE(self, filename):
        try:
            pe =  pefile.PE(filename)
            return pe
        except:
            return None
        
    def get_pe_properties(self, pe):
        properties = []

        properties.append(pe.DOS_HEADER.e_magic)
        properties.append(pe.DOS_HEADER.e_cblp)
        properties.append(pe.DOS_HEADER.e_cp)
        properties.append(pe.DOS_HEADER.e_crlc)
        properties.append(pe.DOS_HEADER.e_cparhdr)
        properties.append(pe.DOS_HEADER.e_minalloc)
        properties.append(pe.DOS_HEADER.e_maxalloc)
        properties.append(pe.DOS_HEADER.e_ss)
        properties.append(pe.DOS_HEADER.e_sp)
        properties.append(pe.DOS_HEADER.e_csum)
        properties.append(pe.DOS_HEADER.e_ip)
        properties.append(pe.DOS_HEADER.e_cs)
        properties.append(pe.DOS_HEADER.e_lfarlc)
        properties.append(pe.DOS_HEADER.e_ovno)
        properties.append(int.from_bytes(pe.DOS_HEADER.e_res, "big"))
        properties.append(pe.DOS_HEADER.e_oemid)
        properties.append(pe.DOS_HEADER.e_oeminfo)
        properties.append(int.from_bytes(pe.DOS_HEADER.e_res2, "big"))
        properties.append(pe.DOS_HEADER.e_lfanew)

        properties.append(pe.FILE_HEADER.Machine)
        properties.append(pe.FILE_HEADER.NumberOfSections)
        properties.append(pe.FILE_HEADER.TimeDateStamp)
        properties.append(pe.FILE_HEADER.PointerToSymbolTable)
        properties.append(pe.FILE_HEADER.NumberOfSymbols)
        properties.append(pe.FILE_HEADER.SizeOfOptionalHeader)
        properties.append(pe.FILE_HEADER.Characteristics)

        for i in range(0, 16):  # directory_entry_types
            try:
                properties.append(pe.OPTIONAL_HEADER.DATA_DIRECTORY[i].Size)
            except:
                properties.append(0)

        properties.append(pe.OPTIONAL_HEADER.Magic)
        properties.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
        properties.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
        properties.append(pe.OPTIONAL_HEADER.SizeOfCode)
        properties.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
        properties.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
        properties.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        properties.append(pe.OPTIONAL_HEADER.BaseOfCode)
        #properties.append(pe.OPTIONAL_HEADER.BaseOfData)
        properties.append(pe.OPTIONAL_HEADER.ImageBase)
        properties.append(pe.OPTIONAL_HEADER.SectionAlignment)
        properties.append(pe.OPTIONAL_HEADER.FileAlignment)
        properties.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        properties.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
        properties.append(pe.OPTIONAL_HEADER.MajorImageVersion)
        properties.append(pe.OPTIONAL_HEADER.MinorImageVersion)
        properties.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
        properties.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
        properties.append(pe.OPTIONAL_HEADER.Reserved1)
        properties.append(pe.OPTIONAL_HEADER.SizeOfImage)
        properties.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
        properties.append(pe.OPTIONAL_HEADER.CheckSum)
        properties.append(pe.OPTIONAL_HEADER.Subsystem)
        properties.append(pe.OPTIONAL_HEADER.DllCharacteristics)
        properties.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
        properties.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
        properties.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
        properties.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
        properties.append(pe.OPTIONAL_HEADER.LoaderFlags)
        properties.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)

        properties.append(pe.NT_HEADERS.Signature)

        try:
            properties.append(len(pe.DIRECTORY_ENTRY_IMPORT))
        except:
            properties.append(0)    
        
        try:
            properties.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
        except:
            properties.append(0)

        section_names = [".textbss", ".text", ".rdata", ".data", ".pdata", ".didat", ".rsrc", ".reloc"]
        for i in range(len(section_names)):
            found = False
            for section in pe.sections:
                if section.Name.decode("utf-8", errors="ignore").find(section_names[i]) != -1:
                    properties.append(section.SizeOfRawData)
                    found = True
                    break
            if not found:
                properties.append(0)

        return properties

    def get_PE_data(self, filename):
        
        pe = self.is_PE(filename)
        if not pe:
            return None
        
        print(filename)

        with open(filename, 'rb') as f:
            filecontent = f.read()
        filelength = len(filecontent)

        properties = []
        #properties.append(filename)
        #properties.append(self.get_md5(filename))
        properties.append(filelength)
        properties.append(self.calculate_entropy(filecontent.decode(errors="ignore")))
        properties.extend(self.get_pe_properties(pe))

        return properties
                    

if __name__ == "__main__":
    la = PropertiesPE()
    bla = la.get_PE_data('D:\\STUDY\\9\\bos\\anti\\2\\StatAnal_Diana\\test\\OfficeClickToRun.exe')

    for p in bla:
        print(p)