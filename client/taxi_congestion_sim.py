
import numpy as np
import os
# import matplotlib.pyplot as plt
# from lib.crypto import decrypt_aes
# from enum import Enum
# import random

# from lib.taxi import Taxi, Map
# import time
# import base64

# from lib.com import deploy_data, send_get_request
# from config import HOSTNAME, PORT

# from lib.crypto import importKey, decryptRsaData
# def decrypt_result(encData):
#     RESULT_KEY_FILE = "./keys/result_key"
#     privKey = importKey(RESULT_KEY_FILE)
#     decrypted = decryptRsaData(encData, privKey)
#     return decrypted

# class Middleware:

#     def __init__(self):
#        self.data = {}

#     def add_data(self, id:int, value):
#        self.data[id] = value; 

#     def get_taxi_positions(self,ids:[]):
#         positions = []
#         for id in ids:
#             positions.append((id, self.data[id]))
#         return positions

#     def compute_distribution(self):
#         data_objects = []
#         for k,v in self.data.items():
#             print(k,v)
#             data_object = {"id":str(k), "data":v}
#             data_objects.append(data_object)
#             print(data_object)
#         deploy_data(data_objects, HOSTNAME, PORT)

#         response = send_get_request('/dist', HOSTNAME, PORT)
#         print("Distrubution raw response:", response)
#         decoded = base64.b64decode(response)
#         result = decrypt_result(decoded)
#         result = result.split(',')
#         result = [int(x) for x in result]
#         print("N taxis:", len(self.data))
#         print("Sum distribution:", sum(result))
#         print("Decrypted:", result)
#         distribution = {}
#         for zone in range(len(result)):
#             if result[zone]==0:
#                 continue
#             print("zone:",zone, 'taxis:', result[zone])
#             zx = zone//10
#             zy = zone%10
#             print("Zone coord:", zx,zy)
#             center = (zx*100+50, zy*100+50)
#             print("Center coord:", center)
#             distribution[center]=result[zone]

#         print(distribution)
#         return distribution



# import json
# class TaxiCompany:

#     def __init__(self,taxis_keys:[],middleware:Middleware):
#         self.taxi_keys = taxis_keys
#         self.middleware = middleware
#         self.color = np.random.rand(1)

#     def get_taxi_ids(self):
#         return self.taxi_keys.keys()

#     def get_taxi_positions(self):
#         position_data = self.middleware.get_taxi_positions(self.taxi_keys.keys())
#         positions = []
#         for id, data in position_data:
#             key = self.taxi_keys[id]
#             iv = base64.b64decode(data['iv'])
#             encrypted = base64.b64decode(data['value'])
#             decrypted = decrypt_aes(encrypted, key, iv)
#             positions.append(json.loads(decrypted))

#         return positions
    
# def create_taxis(n, map, middleware):
#     taxis = []
#     for i in range(n_taxis):
#         x0,y0 = map.get_random_intection()
#         taxis.append(Taxi(x0,y0, i+1, map=map, middleware=middleware))
#     return taxis

# def chunks(lst, n):
#     """Yield successive n-sized chunks from lst."""
#     for i in range(0, len(lst), n):
#         yield lst[i:i + n]

# def get_taxi_ids(taxis:[]):
#     ids = []
#     for taxi in taxis:
#         ids.append(taxi.id)
#     return ids

# def get_taxi_keys(taxis:[]):
#     keys = {}
#     for taxi in taxis:
#         keys[taxi.id]=taxi.key
#     return keys

# def plot_distribution(distrubution,map, ax, colors):
#     lim_offset=5
#     N=len(distrubution)
#     # colors = np.random.rand(N)

#     ticks = list(range(0,map.MAX_X+1,100))
#     fontsize = 12
#     # ax.scatter(x_pos, y_pos, c=colors)
#     x = []
#     y = []
#     values = []
#     area = []
#     max_area = 50*50
#     zone_colors = []
#     print("Colors:", colors)
#     for k,v in distrubution.items():
#         print(k[0], k[1],v)
#         x.append(k[0])
#         y.append(k[1])
#         values.append(v)
#         area.append(v*max_area/N)
#         c = colors[(k[0],k[1])]
#         # plot("Zone color:",c)
        
#         zone_colors.append(colors[(k[0],k[1])])
        
#     ax.scatter(x, y, s=area, c=zone_colors, alpha=0.5)
#     # Annotate value
#     for i in range(N):
#         ax.text(x[i],y[i],str(values[i]), fontsize=fontsize, ha='center', va='center') 

#     # ax.set_xticks(ticks)
#     # ax.set_yticks(ticks)
#     # ax.grid()
#     ax.set_xlim([map.MIN_X-lim_offset,map.MAX_X+lim_offset])
#     ax.set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])

#     print("Plotting dist")

# if __name__ == '__main__':
#     height = 1000
#     width = 1000

#     n_taxis = 10
#     taxis_per_company=5

#     map = Map(height=height, width=width)
#     mw = Middleware()

#     taxis = create_taxis(n_taxis, map, mw)

#     company_taxis = chunks(taxis, taxis_per_company) 
#     companies = []
#     taxi_colors = {}
#     for chunk in company_taxis:
#         keys = get_taxi_keys(chunk)
#         company = TaxiCompany(keys, mw)
#         companies.append(company)
#         color = company.color
#         for taxi in chunk:
#             taxi_colors[taxi.id]=color


#     dist_colors = {}
#     for x in range(50,1000,100):
#         for y in range(50,1000,100):
#             # print(x,y)
#             dist_colors[(x,y)]=np.random.rand(1)[0]

#     print(dist_colors)
#     # exit(0)
#     # print("Here i am")
#     # exit(0)
#     # Deploy keys to middleware
#     for taxi in taxis:
#         taxi.register_key() 
#     # print("Keys deployed")    

#     # Move one step to generate data to middleware 
#     # for t in taxis:
#         # t.move()

#     # Mocked distrubution
#     # distrubution = {(50, 250): 1, (150, 250): 1, (350, 50): 1, (350, 650): 1, (450, 650): 1, (450, 950): 1, (750, 850): 1, (850, 150): 1, (850, 950): 1, (950, 650): 1}
#     # distrubution = mw.compute_distribution()

#     # fig, ax = plt.subplots(1)
#     # plot_distribution(distrubution,map,ax)

#     # plt.show()
#     # plt.draw()
#     # plt.pause(5)
#     # print("All done")
#     # plt.show()
#     # exit(0)
#     # select one company to visualize 
#     company = companies[1]
#     company_colors = []
#     for id in company.get_taxi_ids():
#         company_colors.append(taxi_colors[id])
        
#     T = 1
#     T=20
#     dt = 0.1
#     pause = 1
#     # pause = 5
#     # colors = np.random.rand(n_taxis)
#     fig, ax = plt.subplots(3)
#     plt.axis([m
import matplotlib.pyplot as plt
from lib.crypto import decrypt_aes
from enum import Enum
import random

from lib.taxi import Taxi, Map
import time
import base64

from lib.com import deploy_data, send_get_request, reset_server_data
from config import HOSTNAME, PORT

from lib.crypto import importKey, decryptRsaData
def decrypt_result(encData):
    RESULT_KEY_FILE = "./keys/result_key"
    privKey = importKey(RESULT_KEY_FILE)
    decrypted = decryptRsaData(encData, privKey)
    return decrypted

class Middleware:

    def __init__(self):
       self.data = {}

    def add_data(self, id:int, value):
       self.data[id] = value; 

    def get_taxi_positions(self,ids:[]):
        positions = []
        for id in ids:
            positions.append((id, self.data[id]))
        return positions

    def compute_distribution(self):
        data_objects = []
        for k,v in self.data.items():
            # print(k,v)
            data_object = {"id":str(k), "data":v}
            data_objects.append(data_object)
            # print(data_object)
        
        start = time.time()
        deploy_data(data_objects, HOSTNAME, PORT)
        deploy_time = time.time()-start

        start = time.time()
        response = send_get_request('/dist', HOSTNAME, PORT)
        comp_time = time.time()-start
        elapsed = {'deploy':deploy_time, 'comp':comp_time}

        # print("Distrubution raw response:", response)
        response = response.split('\n')
        # print("Split response:", response)
        decrypted = ''
        for r in response:
            d = base64.b64decode(r)
            dec = decrypt_result(d)
            # print("Partly decoded:", d)
            # print("Partly decrypted:", dec)
            decrypted+=dec
        # print("Decoded:", decoded)
        # print("decrypted:", decrypted)
        result = decrypted
        # result = decrypt_result(decoded)
        result = result.split(',')
        result = [int(x) for x in result]
        # print("N taxis:", len(self.data))
        # print("Sum distribution:", sum(result))
        # print("Decrypted:", result)
        distribution = {}
        for zone in range(len(result)):
            if result[zone]==0:
                continue
            # print("zone:",zone, 'taxis:', result[zone])
            zx = zone//10
            zy = zone%10
            # print("Zone coord:", zx,zy)
            center = (zx*100+50, zy*100+50)
            # print("Center coord:", center)
            distribution[center]=result[zone]

        # print(distribution)
        return distribution, elapsed, result



import json
class TaxiCompany:

    def __init__(self,taxis_keys:[],middleware:Middleware):
        self.taxi_keys = taxis_keys
        self.middleware = middleware
        self.color = np.random.rand(1)

    def get_taxi_ids(self):
        return self.taxi_keys.keys()

    def get_taxi_positions(self):
        position_data = self.middleware.get_taxi_positions(self.taxi_keys.keys())
        positions = []
        for id, data in position_data:
            key = self.taxi_keys[id]
            iv = base64.b64decode(data['iv'])
            encrypted = base64.b64decode(data['value'])
            decrypted = decrypt_aes(encrypted, key, iv)
            positions.append(json.loads(decrypted))

        return positions
    
def create_taxis(n, map, middleware, keys):
    taxis = []
    for i in range(n_taxis):
        x0,y0 = map.get_random_intection()
        taxis.append(Taxi(x0,y0, i+1, map=map, middleware=middleware, key=keys[i]))
    return taxis

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def get_taxi_ids(taxis:[]):
    ids = []
    for taxi in taxis:
        ids.append(taxi.id)
    return ids

def get_taxi_keys(taxis:[]):
    keys = {}
    for taxi in taxis:
        keys[taxi.id]=taxi.key
    return keys

def plot_distribution(distrubution,map, ax, colors):
    lim_offset=5
    N=len(distrubution)
    # colors = np.random.rand(N)

    ticks = list(range(0,map.MAX_X+1,100))
    fontsize = 12
    # ax.scatter(x_pos, y_pos, c=colors)
    x = []
    y = []
    values = []
    area = []
    max_area = 50*50
    zone_colors = []
    # print("Colors:", colors)
    for k,v in distrubution.items():
        # print(k[0], k[1],v)
        x.append(k[0])
        y.append(k[1])
        values.append(v)
        area.append(v*max_area/N)
        c = colors[(k[0],k[1])]
        # plot("Zone color:",c)
        
        zone_colors.append(colors[(k[0],k[1])])
        
    ax.scatter(x, y, s=area, c=zone_colors, alpha=0.5)
    # Annotate value
    for i in range(N):
        ax.text(x[i],y[i],str(values[i]), fontsize=fontsize, ha='center', va='center') 

    # ax.set_xticks(ticks)
    # ax.set_yticks(ticks)
    # ax.grid()
    ax.set_xlim([map.MIN_X-lim_offset,map.MAX_X+lim_offset])
    ax.set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])

    # print("Plotting dist")


_key_storage='./cache/taxi_keys.json'    
def generate_and_store_keys(n=5000):
    keys = []
    for i in range(n):
        key = os.urandom(32)
        encoded = base64.b64encode(key).decode('ascii')    
        keys.append(encoded)

    json_keys = json.dumps(keys)
    with open(_key_storage, "w") as outfile:
        outfile.write(json_keys)

def load_keys(n=5000):
    keys = []
    with open(_key_storage, "r") as openfile:
        json_keys = json.load(openfile)

    for encoded in json_keys:
        key = base64.b64decode(encoded)
        keys.append(key)

    return keys

if __name__ == '__main__':
    reuse_keys = True
    # reuse_keys = False
    height = 1000
    width = 1000

    n_taxis = 100
    taxis_per_company=10

    # Clear previously stored data, if any
    reset_server_data(HOSTNAME, PORT)

    # Should only need to be done once, and only to save time during dev
    # generate_and_store_keys()
    keys = load_keys()

    map = Map(height=height, width=width)
    mw = Middleware()

    taxis = create_taxis(n_taxis, map, mw, keys)

    company_taxis = chunks(taxis, taxis_per_company) 
    companies = []
    taxi_colors = {}
    for chunk in company_taxis:
        keys = get_taxi_keys(chunk)
        company = TaxiCompany(keys, mw)
        companies.append(company)
        color = company.color
        for taxi in chunk:
            taxi_colors[taxi.id]=color


    dist_colors = {}
    for x in range(50,1000,100):
        for y in range(50,1000,100):
            # print(x,y)
            dist_colors[(x,y)]=np.random.rand(1)[0]

    # print(dist_colors)
    # exit(0)
    # print("Here i am")
    # exit(0)
    # Deploy keys to middleware
    if not reuse_keys:
        for taxi in taxis:
            taxi.register_key() 
    # print("Keys deployed")    

    # Move one step to generate data to middleware 
    # for t in taxis:
        # t.move()

    # Mocked distrubution
    # distrubution = {(50, 250): 1, (150, 250): 1, (350, 50): 1, (350, 650): 1, (450, 650): 1, (450, 950): 1, (750, 850): 1, (850, 150): 1, (850, 950): 1, (950, 650): 1}
    # distrubution = mw.compute_distribution()

    # fig, ax = plt.subplots(1)
    # plot_distribution(distrubution,map,ax)

    # plt.show()
    # plt.draw()
    # plt.pause(5)
    # print("All done")
    # plt.show()
    # exit(0)
    # select one company to visualize 
    company = companies[1]
    company_colors = []
    for id in company.get_taxi_ids():
        company_colors.append(taxi_colors[id])
        
    T = 1
    T=100
    dt = 0.1
    pause = 1
    # pause = 5
    # colors = np.random.rand(n_taxis)
    fig, ax = plt.subplots(3)
    # plt.axis([map.MIN_X-1, map.MAX_X+1, map.MIN_Y-1, map.MAX_Y+1])
    plt.axis([0, 100, 0, 100])
    # fig.canvas.set_window_title("Taxi position data")

    ticks = list(range(0,map.MAX_X+1,10))
    ticks = list(range(0,map.MAX_X+1,100))
    colors = []
    for t in taxis:
        colors.append(taxi_colors[t.id])

    dist_colors = {}
    for x in range(50,1000,100):
        for y in range(50,1000,100):
            # print(x,y)
            dist_colors[(x,y)]=np.random.rand(1)[0]

    # dist_colors = np.random.rand(100)
    simulation_data = []
    dist_time = []
    for t in range(T):
    # while True:
        sim_data = {}
        print("Time step:", t)
        x_pos = []
        y_pos = []
        taxi_sim_data = []
        for t in taxis:
            t.move()
            x,y = t.get_pos()
            x_pos.append(x)
            y_pos.append(y)
            id = t.get_id()
            taxi_sim_data.append([x,y,id])
        sim_data['taxis']=taxi_sim_data
        company = companies[1]
        positions = company.get_taxi_positions()
        company_x = [i[0] for i in positions]
        company_y = [i[1] for i in positions]
        

        ax[0].title.set_text("Global view")
        ax[0].scatter(x_pos, y_pos, c=colors)
        ax[0].set_xticks(ticks)
        ax[0].set_yticks(ticks)
        ax[0].grid()
        lim_offset=5
        ax[0].set_xlim([map.MIN_X-lim_offset,map.MAX_X+lim_offset])
        ax[0].set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])
        # ax[0].set_xlim([0,100])
        # ax[0].set_ylim([0,100])
        # ax[0].set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])


        ax[1].title.set_text("Company view")
        ax[1].scatter(company_x, company_y, c=company_colors)
        ax[1].set_xticks(ticks)
        ax[1].set_yticks(ticks)
        ax[1].grid()
        ax[1].set_xlim([map.MIN_X-lim_offset,map.MAX_X+lim_offset])
        ax[1].set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])

        # start = time.time()
        distrubution, elapsed_time,result = mw.compute_distribution()
        
        sim_data['distribution']=result
        sim_data['distribution_time']=elapsed_time
        # elapsed = time.time()-start
        # print("Elapsed time:", elapsed)
        dist_time.append(elapsed_time)
        

        # fig, ax = plt.subplots(1)
        ax[2].title.set_text("Public view")
        ax[2].set_xticks(ticks)
        ax[2].set_yticks(ticks)
        ax[2].grid()
        plot_distribution(distrubution,map,ax[2],dist_colors)

        
        plt.draw()
        plt.pause(dt*pause)

        ax[0].cla()
        ax[1].cla()
        ax[2].cla()
        simulation_data.append(sim_data)


    json_data = json.dumps(simulation_data)
    fname = "taxi-simulation-" + str(n_taxis) + "-" + time.strftime("%Y%m%d-%H%M%S") + '.json'
    with open(fname, "w") as outfile:
        outfile.write(json_data)
   
    print("End of simulation")
    # print("Number of iterations:", T)
    # print("Number of taxis:", n_taxis)
    # import statistics
    # print("Mean time of distribution computation time:", statistics.mean(dist_time))
    # plt.show()


