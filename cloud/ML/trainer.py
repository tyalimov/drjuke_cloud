import sys
import csv
import random
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import precision_score, recall_score, roc_auc_score, roc_curve

def read_data(filename):
    labels = []
    data = []
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            labels.append(row[0])
            data.append(row[3:])

    return labels, data

def separete_dataset(labels, data, percentage = 0.85):
    train_labels = []
    train_data = []
    test_labels = []
    test_data = []

    for label, dat in zip(labels, data):
        if random.random() < percentage:
            train_labels.append(label)
            train_data.append(dat)
        else:
            test_labels.append(label)
            test_data.append(dat)

    return train_labels, train_data, test_labels, test_data

def method_chi2(data, labels, test):
    selecter = SelectKBest(score_func=mutual_info_classif, k=20)
    selecter.fit(data, labels)
    param = selecter.get_support()
    print(len(param), param)
    pickle.dump(param, open('param', 'wb'))
    return selecter.transform(data),selecter.transform(test)

def classifire(train_labels, train_data, test_labels, test_data):
    train_data,test_data=method_chi2(train_data,train_labels,test_data)
    model = RandomForestClassifier(n_estimators=100, random_state=50, max_features = "auto", n_jobs=-1, verbose = 1, max_depth = 100)
    model.fit(train_data, train_labels)

    filename = 'finalized_model.sav'
    pickle.dump(model, open(filename, 'wb'))

    loaded_model = pickle.load(open(filename, 'rb'))
    print(loaded_model.score(train_data, train_labels))
    print(loaded_model.score(test_data, test_labels))

if __name__ == "__main__":
    labels, data = read_data(sys.argv[1])
    train_labels, train_data, test_labels, test_data = separete_dataset(labels, data)
    print(len(train_labels), len(train_data), len(test_labels), len(test_data))
    classifire(train_labels, train_data, test_labels, test_data)