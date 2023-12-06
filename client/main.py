import argparse

from lib.data_generation import generate_rand_ints

from lib.com import get_payload_string, Method, Content_type, send_raw_data

import json

from lib.io import import_json
#from config import HOSTNAME, PORT

from config import HOSTNAME, SECURE_PORT, NON_SECURE_PORT

_users = []
REUSE_KEYS = True

# Debug function
def print_hex(m):
    for c in m:
        print(hex(c)," ",  end='')
    print()


# Decrypt result with specified RSA key
from lib.crypto import importKey, decryptRsaData
def decrypt_result(encData):
    RESULT_KEY_FILE = "./keys/result_key"
    privKey = importKey(RESULT_KEY_FILE)
    decrypted = decryptRsaData(encData, privKey)
    return decrypted

from lib.user import User

def generate_packets(method, endpoint, data):
    #TLS_BUFFER_SIZE = 16384;
    # SOURCE: https://www.oreilly.com/library/view/high-performance-browser/9781449344757/ch04.html
    TLS_BUFFER_SIZE = 16000;
    packets = []
    tmp_data = []
    for d in data:
        packet = get_payload_string(json.dumps(tmp_data+[d]), path=endpoint, method=method, content_type=Content_type.json)
        if len(packet)<TLS_BUFFER_SIZE:
            tmp_data.append(d)
        else:
            packets.append(packet)
            tmp_data = []
    if len(tmp_data)>0:
        packets.append(get_payload_string(json.dumps(tmp_data), path=endpoint, method=method, content_type=Content_type.json))

    return packets

def deploy_key(user:User):
    method = Method.post
    endpoint = "/key"
    
    body = user.get_key_json()
    payload = get_payload_string(json.dumps(body), path=endpoint, method=method, content_type=Content_type.json)

    return send_raw_data(payload, HOSTNAME, PORT)

def deploy_keys(users):
    for user in users:
        deploy_key(user)

def deploy_data(data_objects):
    method = Method.post
    endpoint = '/data'
    packets = generate_packets(method, endpoint, data_objects)

    success = True
    for packet in packets:
        response = send_raw_data(packet, HOSTNAME, PORT)
        success = (response == b'HTTP/1.0 200 OK\n\rContent-Type: text/html\n\r\n\rPOST request recieved')
        if not success:
            print("ERROR:", response)
            break
    return success


from lib.user import create_users, create_data_objects

def send_get_request(endpoint):
    method = Method.get
    payload = get_payload_string("", path=endpoint, method=method, content_type=Content_type.text)
    response = send_raw_data(payload, HOSTNAME, PORT)
    return response.decode()

def reset_server_data():
    send_get_request('/clear')

import time
def setup_and_deploy(values, encrypted):
    global _users
    key_deployment_time = None
    data_deployment_time = None
    # start_time = time.time()
    reset_server_data()

    keys_reused = False
    if encrypted and REUSE_KEYS and len(_users)>=len(values):
        keys_reused = True
        users = _users[:len(values)]

        for i in range(len(values)):
            value = values[i]
            user = users[i]
            user.update_data(value)
            
    else:
        users = create_users(values, encrypted=encrypted)
        if REUSE_KEYS and encrypted:
            _users = users
    data = create_data_objects(users)

    if encrypted:
        if keys_reused:
            key_deployment_time = "N/A"
        else:
            start_time = time.time()
            deploy_keys(users)
            key_deployment_time = time.time()-start_time

    start_time = time.time()
    deploy_data(data)
    data_deployment_time = time.time()-start_time

    return key_deployment_time, data_deployment_time


import base64
def compute_sum(is_encrypted:bool, n:int):
    values = generate_rand_ints(n, min_v=1000, max_v=100000)

    key_deployment_time, data_deployment_time = setup_and_deploy(values, is_encrypted)

    start_time = time.time()
    response = send_get_request('/sum')
    computation_time = time.time()-start_time
 
    if is_encrypted:
        decoded = base64.b64decode(response)
        result = decrypt_result(decoded)
    else:
        result = response
    
    # assert int(result)==sum(values)
    if int(result)!=sum(values):
        print("ERROR COMPUTING SUM")
        print("Expected:", sum(values), "Acctual:", int(result))
        exit(0)
    
    return key_deployment_time, data_deployment_time, computation_time, result
    

def compute_histogram(is_encrypted, n):
    values = generate_rand_ints(n, min_v=0, max_v=100)

    key_deployment_time, data_deployment_time = setup_and_deploy(values, is_encrypted)

    start_time = time.time()
    response = send_get_request('/hist')
    computation_time = time.time()-start_time

    if is_encrypted:
        decoded = base64.b64decode(response)
        result = decrypt_result(decoded)
    else:
        result = response
        
    result = result.split(',')
    result = list(map(lambda x: int(x), result))
        
    assert sum(result)==len(values)

    return key_deployment_time, data_deployment_time, computation_time, result



def generate_svm_data(n):
    TEST_DATA_FILE = 'data/breast-cancer.tst.scale'
    fname = TEST_DATA_FILE
    with open(fname,'r') as f:
        data = f.read()

    base_data = data.split('\n')

    # Remove empty entries
    base_data = list(filter(lambda x:len(x)>0, base_data))
    
    indexes = generate_rand_ints(n, min_v=0, max_v=len(base_data)-1)
    data = []
    for index in indexes:
        data.append(base_data[index]+'\n\0')
    return data

def compute_svm(is_encrypted, n):
    values = generate_svm_data(n)

    key_deployment_time, data_deployment_time = setup_and_deploy(values, is_encrypted)

    start_time = time.time()
    response = send_get_request('/svm')
    computation_time = time.time()-start_time

    if is_encrypted: # Decrypt response
        encoded = response.split('\n\r\n\r')[-1]

        full_result=''
        chunks = encoded.split('\n')
        chunks = list(filter(lambda x:len(x)>0, chunks))
        for chunk in chunks:
            decoded = base64.b64decode(chunk)
            result = decrypt_result(decoded)
            full_result+=result

        classifications = full_result.split(',')

    else:
        classifications = response.split(',')

    assert len(classifications)==len(values)

    return key_deployment_time, data_deployment_time, computation_time, classifications


import random
def generate_coordinates(n,min_v, max_v):
    coord = []
    for i in range(n):
        coord.append((random.uniform(min_v, max_v),random.uniform(min_v, max_v)))
    return coord

def compute_lsf(is_encrypted, n):
    values = generate_coordinates(n, min_v=-100, max_v=100)
    key_deployment_time, data_deployment_time = setup_and_deploy(values, is_encrypted)
    
    start_time = time.time()
    response = send_get_request('/lsf')
    computation_time = time.time()-start_time

    if is_encrypted:
        decoded = base64.b64decode(response)
        result = decrypt_result(decoded)
    else:
        result = response

    result = result.split(',')

    assert len(result)==2

    return key_deployment_time, data_deployment_time, computation_time, result



def test_all():
    global PORT
    n=150;
    functions = [compute_sum, compute_svm, compute_lsf, compute_histogram]
    names = ["SUM COMPUTATION", "SVM COMPUTATION", "LSF COMPUTATION", "HISTOGRAM COMPUTATION"]
    
    for is_encrypted in [True, False]:
        PORT = SECURE_PORT if is_encrypted else NON_SECURE_PORT
        for i in range(len(functions)):
            key_dep_time, data_dep_time, comp_time, result = functions[i](is_encrypted, n)

            title = "SECURE " + names[i]
            if not is_encrypted:
                title = "NON-" + title

            print("-----",title,"-----")
            if is_encrypted:
                print("Key deployment time:", key_dep_time)
            print("Data deployment time:", data_dep_time)
            print("Computation time:", comp_time)
            print("-------------------")

        # compute_sum(is_encrypted, n)
        # print()
        # compute_svm(is_encrypted, n)
        # print()
        # compute_lsf(is_encrypted, n)
        # print()
        # compute_histogram(is_encrypted, n)


from tqdm import tqdm
from statistics import mean
import numbers
def run_benchmark(n=1000, it=100):
    global PORT
    # n=1000;
    # it = 10;
    functions = [compute_sum, compute_svm, compute_lsf, compute_histogram]
    pretty_names = ["SUM COMPUTATION", "SVM COMPUTATION", "LSF COMPUTATION", "HISTOGRAM COMPUTATION"]
    names = ["SUM_COMPUTATION", "SVM_COMPUTATION", "LSF_COMPUTATION", "HISTOGRAM_COMPUTATION"]

    # functions = [compute_svm, compute_lsf, compute_histogram]
    # names = ["SVM COMPUTATION", "LSF COMPUTATION", "HISTOGRAM COMPUTATION"]

    # functions = [compute_svm, compute_lsf, compute_histogram, compute_sum]
    # names = ["SVM COMPUTATION", "LSF COMPUTATION", "HISTOGRAM COMPUTATION", "SUM COMPUTATION"]

    secure_result = {}
    non_secure_result = {}
    for i in range(len(functions)):    
        for is_encrypted in [True, False]:
            PORT = SECURE_PORT if is_encrypted else NON_SECURE_PORT
            title = "SECURE " + pretty_names[i]
            if not is_encrypted:
                title = "NON-" + title


            key_time = []
            data_time = []
            comp_time = []
            for ii in tqdm (range(it), desc="Running " + title + " TEST"):
                key_dep_time, data_dep_time, computation_time, result = functions[i](is_encrypted, n)
                if isinstance(key_dep_time, numbers.Number):
                    key_time.append(key_dep_time)
                data_time.append(data_dep_time)
                comp_time.append(computation_time)

            print("-----",title,"-----")
            if is_encrypted and len(key_time)>0:
                print("Key deployment time:", mean(key_time))
            print("Data deployment time:", mean(data_time))
            print("Computation time:", mean(comp_time))
            print("-------------------")

            # Store result
            if is_encrypted:
                secure_result[names[i]] = {}
                secure_result[names[i]]['key_time']=key_time
                secure_result[names[i]]['data_time']=data_time
                secure_result[names[i]]['comp_time']=comp_time
            else:
                non_secure_result[names[i]] = {}
                non_secure_result[names[i]]['key_time']=key_time
                non_secure_result[names[i]]['data_time']=data_time
                non_secure_result[names[i]]['comp_time']=comp_time

    result = {}
    result['secure'] = secure_result
    result['non_secure'] = non_secure_result
    result['n'] = n
    result['it'] = it

    folder = "benchmark-results"
    fname = "benchmark-" + time.strftime("%Y%m%d-%H%M%S") + '.json'
    print("Storing result as", fname, "in folder", folder)
    # Serializing json
    json_object = json.dumps(result, indent=4)
 
    # Writing to sample.json
    with open(folder + '/' + fname, "w") as outfile:
        outfile.write(json_object)

    # Store copy as latest
    fname = "benchmark-" + 'latest' + '.json'
    with open(folder + '/' + fname, "w") as outfile:
        outfile.write(json_object)

    # print("Result json:")
    # print(json.dumps(
    #     result,
    #     sort_keys=True,
    #     indent=4,
    #     separators=(',', ': ')
    # ))

## Python program to understand the usage of tabulate function for printing tables in a tabular format
# from tabulate import tabulate
# data = [[1, 'Liquid', 24, 12],
# [2, 'Virtus.pro', 19, 14],
# [3, 'PSG.LGD', 15, 19],
# [4,'Team Secret', 10, 20]]
# print (tabulate(data, headers=["Pos", "Team", "Win", "Lose"]))
#from tabulate import tabulate, SEPARATING_LINE
from tabulate import tabulate
def print_stats(func_name, secure_res, plain_res,n):
    headers = ["Function", "Type", "Data Deployment", "Computation"]
    print(headers)
    return
    key_time = secure_res["key_time"]
    data_dep_time = secure_res["data_time"]
    comp_time = secure_res["comp_time"]
    print("---- |",func_name,"| ----")
    if len(key_time)>0:
        print("Mean key deployment time:", mean(key_time), "s")
        print("Mean key deployment time per user:", mean(key_time)/n, "s")

    print("Mean data deployment time:", mean(data_dep_time))
    print("Mean computation deployment time:", mean(comp_time))
    print("---------------")

# Compute geometric mean
# Source: https://stackoverflow.com/questions/43099542/python-easy-way-to-do-geometric-mean-in-python
def geo_mean_overflow(iterable):
    return np.exp(np.log(iterable).mean())


def geometric_mean(data):
    cases = ['secure_sum', 'svm', 'histogram','lsf']
    all_results = []
    for case in cases:
        pass


def vec_sum(v1, v2):
    s = []
    assert len(v1)==len(v2)
    for i in range(len(v1)):
        s.append(v1[i]+v2[i])
    return s

def format_data(data, scale=None):
    deployment_time = data["data_time"]
    computation_time = data["comp_time"]
    if scale:
        deployment_time = list(map(lambda x: x * scale, deployment_time))
        computation_time = list(map(lambda x: x * scale, computation_time))

    total_time = vec_sum(deployment_time, computation_time)
    return deployment_time, computation_time, total_time

import statistics as stats
import numpy as np
def analyze_data():
    print("SHould analyze data")
    fname = "benchmark-results/benchmark-latest.json"
    data = import_json(fname)
    pretty_names = {"SUM_COMPUTATION":"Sum", "SVM_COMPUTATION":"SVM", "LSF_COMPUTATION":"LSF", "HISTOGRAM_COMPUTATION":"Histogram"}
    print(data.keys())
    print("Analysing file:", fname)
    print("Number of iterations:", data["it"])
    print("Number of users:", data["n"])

    secure = data["secure"]
    plain = data["non_secure"]

    all_secure_time = []
    all_plain_time = []
    overhead = {}
    table = []
    for comp in secure.keys():
        deploy_time, comp_time, total = format_data(secure[comp],scale=1000)
        all_secure_time+=total
        sec_total = total
        fname = pretty_names[comp]
        sec_row = [fname, "Enclave", mean(deploy_time), mean(comp_time), mean(total),stats.pstdev(total)]
        
        deploy_time, comp_time, total = format_data(plain[comp], scale=1000)
        all_plain_time+=total
        plain_total = total
        #plain_row = ['', "Enclave", mean(plain[comp]["data_time"]), mean(plain[comp]["comp_time"])]
        plain_row = ['', "Plain", mean(deploy_time), mean(comp_time), mean(total),stats.pstdev(total)]

        overhead[fname]=mean(sec_total)/mean(plain_total)
        table.append(sec_row)
        table.append(plain_row)
        #table.append('----------------------')

        # print("Function", comp)
        # print(secure[comp].keys())
        # key_time = secure[comp]["key_time"]
        # data_dep_time = secure[comp]["data_time"]
        # comp_time = secure[comp]["comp_time"]
        # if len(key_time)>0:
        #     print("Mean key deployment time:", mean(key_time), "s")
        #     print("Mean key deployment time per user:", mean(key_time)/data["n"], "s")

        # print("Mean data deployment time:", mean(data_dep_time))
        # print("Mean computation deployment time:", mean(comp_time))

        # print("-----------------")
    for row in table:
        print(row)
    headers = ["Function", "Type", "Deployment", "Computation", "Total", "STD"]
    #print (tabulate(table, headers=headers, tablefmt="latex_raw", floatfmt=".2f"))
    print (tabulate(table, headers=headers, floatfmt=".0f", tablefmt="latex"))

    secure_geo_mean = geo_mean_overflow(all_secure_time)
    plain_geo_mean = geo_mean_overflow(all_plain_time)
    print("Secure geometric mean:", secure_geo_mean)
    print("Plain geometric mean:", plain_geo_mean)
    print("Geometric overhead:", secure_geo_mean/plain_geo_mean)
    print("Overhead:", overhead)
    #    print_stats(comp, secure[comp], plain[comp], data["n"])
    
    

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    # parser.add_argument("echo")
    args = parser.parse_args()

    n=150;
    version = 'secure'
    version = 'non-secure'

    if version=='secure':
        PORT = SECURE_PORT
        is_encrypted = True
    elif version=='non-secure':
        PORT = NON_SECURE_PORT
        is_encrypted=False
    else:
        print("Invalid version:", version)
        exit(0)
        
    #compute_sum('non-secure')
    #compute_sum('secure')

    #compute_histogram('secure')
    #compute_histogram('non-secure')
    
    #compute_lsf('secure')
    #compute_lsf('non-secure')

    #compute_svm('non-secure')

    #compute_svm(is_encrypted, n)
    #compute_sum(is_encrypted, n)
    #compute_lsf(is_encrypted, n)
    #compute_histogram(is_encrypted, n)
    #test_all()
    #run_benchmark(n=5000, it=100)
    analyze_data()
