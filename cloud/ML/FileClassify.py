import pickle
import numpy as np
from PropertiesPE import PropertiesPE


class FileClassify():

    def __init__(self):
        self.model = pickle.load(open('model.sav', 'rb'))
        self.param = pickle.load(open('param', 'rb'))

    def __get_best_param(self, proper):
        best_proper = []
        for i in range(len(self.param)):
            if self.param[i] == True:
                best_proper.append(proper[i])
        print(len(best_proper))
        return best_proper

    def isMalware(self, filename):
        try:
            propPE = PropertiesPE()
            proper = propPE.get_PE_data(filename)
            proper = self.__get_best_param(proper)

            result = self.model.predict(np.array(proper).reshape(1, -1))
            return result[0]
        except:
            return None


if __name__ == "__main__":
    import sys
    bla = FileClassify()
    result = bla.isMalware(sys.argv[1])
    print(result)
