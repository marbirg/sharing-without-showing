import ssl
import socket
import json
from enum import Enum

class Method(Enum):
    get="GET"
    post="POST"

    def __str__(self):
        return '{0}'.format(self.value)

class Content_type(Enum):
    text = "application/text"
    json = "application/json"

    def __str__(self):
        return '{0}'.format(self.value)

def get_payload_string(payload, method=Method.get, path="/", host="myhost.com", content_type=Content_type.text):
    content_length = len(payload)
    payload_string = \
        "{method} {path} HTTP/1.1\r\n"     \
        "Host: {host}\r\n"                      \
        "Content-Type: {content_type}\r\n"        \
        "Content-Length: {content_length}\r\n\r\n".format(method=method, path=path, host=host, content_type=content_type, content_length=str(content_length))+\
        payload
    return payload_string

def send_raw_data(data, HOSTNAME, PORT):
    return send_raw_byte_data(data.encode(), HOSTNAME, PORT)
                       
def send_raw_byte_data(data, HOSTNAME, PORT):
    #TLS_BUFFER_SIZE = 16000;
    TLS_BUFFER_SIZE = 16384;
    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOSTNAME, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOSTNAME) as ssock:
            # print(ssock.version())
            # print("Open connection to host:", HOSTNAME, PORT)
            # print("Sending:", data)
            # print("As hex:\n",' '.join('{:02x}'.format(x) for x in data))
            ssock.send(data);
            # Receive data from server
            #dataFromServer = ssock.recv(1024);
            dataFromServer = ssock.recv(TLS_BUFFER_SIZE);
            # Print to the console
            #print("Response:", dataFromServer.decode());
            #print("Response length:", len(dataFromServer));
            # raw_result = dataFromServer

    # ssl_sock.connect(("52.136.212.149", 12341))
    # print("socket done")
    return dataFromServer

def add_key(id, key, HOSTNAME, PORT):
    data = {}
    data["id"] = str(id)
    data["key"] = key
    data_string = json.dumps(data)
    payload = "POST /addkey HTTP/1.1\r\n\r\n"     \
    "Host: myhost.com\r\n"                      \
    "Content-Type: application/json\r\n"        \
    "Content-Length: 80\r\n\r\n"+               \
    data_string;
    return send_raw_data(payload, HOSTNAME, PORT)


def deploy_key(key_obj, hostname, port):
    """
    Requires dict on form {"id", id:str, "key": str}
    """
    method = Method.post
    endpoint = "/key"

    payload = get_payload_string(json.dumps(key_obj), path=endpoint, method=method, content_type=Content_type.json)

    return send_raw_data(payload, hostname, port)

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

def deploy_data(data_objects, hostname, port):
    method = Method.post
    endpoint = '/data'
    packets = generate_packets(method, endpoint, data_objects)

    success = True
    for packet in packets:
        response = send_raw_data(packet, hostname, port)
        success = (response == b'HTTP/1.0 200 OK\n\rContent-Type: text/html\n\r\n\rPOST request recieved')
        if not success:
            print("ERROR:", response)
            break
    return success

def send_get_request(endpoint, hostname, port):
    method = Method.get
    payload = get_payload_string("", path=endpoint, method=method, content_type=Content_type.text)
    response = send_raw_data(payload, hostname, port)
    return response.decode()

def reset_server_data(hostname, port):
    send_get_request('/clear', hostname, port)
