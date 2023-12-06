import json
from datetime import datetime

def readFile(fname):
    with open(fname) as f:
        data = f.read()
    return data

def readBinFile(fname):
    with open(fname, mode='rb') as file: # b is important -> binary
        binData = file.read()
    return binData


def import_json(fname):
    with open(fname, 'r') as file:
        json_obj = json.loads(file.read())
    return json_obj

def save_json(fname, data, suffix=True):
    if suffix:
        now = datetime.now()
        date_time = now.strftime("%Y-%m-%d_%H:%M:%S")
        fname = fname.split(".json")[0]
        fname = fname+'_'+date_time+'.json'
        # date_time_obj = datetime.strptime(str(date), '%Y-%m-%d %H:%M:%S')
        print(fname)
    with open(fname, 'w') as file:
        json.dump(data, file, indent=4)
