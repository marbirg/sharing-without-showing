import os
import base64
from lib.crypto import encrypt_aes
class User:
    _KEY_SIZE = 32

    def __init__(self, user_id, data, encrypted=False):
        self.user_id = str(user_id)
        self.data = str(data)
        self.is_encrypted = encrypted

        if encrypted:
            self.key = os.urandom(32)
            self.encrypted, self.iv = encrypt_aes(self.data, self.key)

            self.encoded = base64.b64encode(self.encrypted).decode('ascii')

            self.encoded_iv =  base64.b64encode(self.iv).decode('ascii')

    def update_data(self, data):
        self.data = str(data)
        if self.is_encrypted:
            self.encrypted, self.iv = encrypt_aes(self.data, self.key)
            self.encoded = base64.b64encode(self.encrypted).decode('ascii')
            self.encoded_iv =  base64.b64encode(self.iv).decode('ascii')
        

    def test_decrypt(self):
        iv = base64.b64decode(self.encoded_iv)
        encrypted = base64.b64decode(self.encoded)
        decrypted = decrypt(encrypted, self.key, iv)
        print("Decrypted:", decrypted, "Original:", self.data, "Success:", decrypted==self.data)

    def get_data_json(self):
        json_obj = {"id":self.user_id}
        if self.is_encrypted:
            data_obj = {"len":len(self.encrypted), "iv":self.encoded_iv, "value":self.encoded}
        else:
            data_obj = {"value":self.data}
            
        json_obj = {"id":self.user_id, "data":data_obj}
        return json_obj

    def get_key_json(self):
        b64_key = base64.b64encode(self.key).decode('ascii')    
        return {"id":self.user_id, "key":b64_key}    


def create_users(values, encrypted=True):
    users = []
    for i in range(len(values)):
        users.append(User(i+1, str(values[i]), encrypted=encrypted))

    return users

def create_data_objects(users:list):
    data = []
    for user in users:
        data.append(user.get_data_json())

    return data
