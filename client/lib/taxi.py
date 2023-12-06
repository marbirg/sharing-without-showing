
import random
from enum import Enum
from lib.crypto import encrypt_aes
import base64
import os

from lib.com import deploy_key
from config import HOSTNAME, PORT

class Map:

    class Direction(Enum):
        Left = (-1,0)
        Right = (1,0)
        Up = (0,1)
        Down = (0, -1)

    MIN_X = 0
    MIN_Y = 0
    MAX_X = 100
    MAX_Y = 100
    INTERSECTION = 10
    directions = []

    def __init__(self, height, width):
        self.directions = [self.Direction.Left, self.Direction.Right, self.Direction.Up, self.Direction.Down]
        self.MAX_Y = height
        self.MAX_X = width
   
    def get_directions(self):
        return [self.Direction.Left, self.Direction.Right, self.Direction.Up, self.Direction.Down]

    def get_valid_directions(self, x,y):
        # directions = [Direction.Up, Direction.Down, Direction.Left, Direction.Right]
        # print("Map directions:", self.directions)
        valid = []
        for d in self.directions:
            x1,y1 = self.get_next_pos(x,y,d)
            if self.is_valid_pos(x1,y1):
                valid.append(d)
        return valid

    def get_next_pos(self, x,y,dir):
        return x+dir.value[0], y+dir.value[1]

    def is_out_of_bounds(self,x,y):
        return x<self.MIN_X or y<self.MIN_Y or x>self.MAX_X or y>self.MAX_Y

    def is_valid_pos(self, x,y):
        return not self.is_out_of_bounds(x,y)

    def is_intersection(self,x,y):
        return x%self.INTERSECTION==0 and y%self.INTERSECTION==0

    def get_random_intection(self):
        # return 10,10
        x0 = round(random.randint(self.MIN_X, self.MAX_X)/self.INTERSECTION)*self.INTERSECTION
        y0 = round(random.randint(self.MIN_Y, self.MAX_Y)/self.INTERSECTION)*self.INTERSECTION
        # y0 = random.randint(MIN_Y, MAX_Y)
        # x0=round(x0/10)*10
        # y0=round(y0/10)*10
        return x0,y0

class Taxi:

    # _key = None
    # dir = None
    # x = 0
    # y = 0
    # id=None


    def __init__(self, x:int, y:int, id:int, middleware, map:Map, key):
        assert id>0
        self.id = id
        # self.key = os.urandom(32)
        self.key = key
        string = "Creating taxi with pos ({x}, {y}) and direction {dir}"
        self.x=x
        self.y=y
        self.map = map
        
        # if not map:
        #     self.map = map
        # else:
        #     self.map = Map()

        # print(map)
        self.dir = random.choice(self.map.get_directions())
        self.middleware = middleware
        # print("Dir:", x_dir, y_dir)
        # print(string.format(x=self.x, y=self.y, dir=self._dir)) 

    def move(self):
        # if (self.x%INTERSECTION==0 and self.y%INTERSECTION==0):
        if (self.map.is_intersection(self.x,self.y)):
            directions = self.map.get_valid_directions(self.x,self.y)
            self.dir = random.choice(directions)

        self.x, self.y = self.map.get_next_pos(self.x,self.y,self.dir)

        if self.map.is_out_of_bounds(self.x,self.y):
            raise Exeption("Coordinates out of bounds")

        value = str([self.x, self.y])

        # print("Non encrypted value",value, self.id)
        # Encrypt data and uppload to middleware
        self.encrypted, self.iv = encrypt_aes(value, self.key)
        self.encoded = base64.b64encode(self.encrypted).decode('ascii')
        self.encoded_iv =  base64.b64encode(self.iv).decode('ascii')
        data_obj = {"len":len(self.encrypted), "iv":self.encoded_iv, "value":self.encoded}

        self.middleware.add_data(self.id, data_obj)
        # if self.x<MIN_X:
        #     raise Exception("X too small")
        # if self.x>MAX_X:
        #     raise Exception("X too large")
        # if self.y<MIN_Y:
        #     raise Exception("Y too small")
        # if self.y>MAX_Y:
        #     raise Exception("Y too large")

    def get_pos(self):
        return self.x,self.y
    def get_id(self):
        return self.id

    def register_key(self):
        b64_key = base64.b64encode(self.key).decode('ascii')    
        key_obj = {"id":str(self.id), "key":b64_key}    
        response = deploy_key(key_obj, HOSTNAME, PORT)
        print("Key deployment response:", response)

