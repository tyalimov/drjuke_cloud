'''
скрипт для создания csv
скрипт для тренировки
скрипт для проверки файла на готовой модели
'''
import glob
import sys
import csv
from PropertiesPE import PropertiesPE


def get_data(path, malware):
    properties = []
    files = glob.glob(path + '\\*')
    for file in files:
        PE = PropertiesPE()
        prop = PE.get_PE_data(file)
        if prop:
            prop.insert(0, malware)
            properties.append(prop)
    
    return properties

def create_csv(set):

    for d in set:
        print(d)

    with open("dataset.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(set)

def create_dataset(path_to_clean, path_to_malware):
    clean = get_data(path_to_clean, 0)
    malware = get_data(path_to_malware, 1)

    for i in clean:
        print(i)
    clean.extend(malware)
    create_csv(clean)

if __name__ == "__main__":
    create_dataset(sys.argv[1], sys.argv[2])
