// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.


#include <mbedtls/certs.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/x509.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../common/common.h"

#include "string"

//#include "../../common/cpp-base64/base64.h"

// For GSL Histograms
#include <gsl_histogram.h>
#include <fit/gsl_fit.h>

// For libSvm:
#include "../../libsvm/svm.h"
#include "../../libsvm/svm.cpp"
#include "../../libsvm/models.c"
#include "../../libsvm/data.c"
#include "../../libsvm/svm-predict-lib.c"

bool DEBUG = false;

// Json parsing
#include "../common/nlohmann/json.hpp"
using json = nlohmann::json;
json DATA;

extern "C"
{
    int set_up_tls_server(char* server_port, bool keep_server_up);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
int TLS_BUFFER_SIZE = 16384;// Max size for TLS packet
//unsigned char buf[TLS_BUFFER_SIZE];

// ------- HELP FUNCTIONS -----------
void print_hex(const char* data){
  int i = 0;
  while (data[i]!='\0'){
    printf("%02x ", data[i]);
    i++;
  }
  printf("\n");
}

void print_hex(const unsigned char* data, int n){
  int i = 0;
  for (i=0; i<n; i++){
    printf("%02x ", data[i]);
  }
  printf("\n");
}

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);

#define SERVER_IP "0.0.0.0"

static void my_debug(
    void* ctx,
    int level,
    const char* file,
    int line,
    const char* str)
{
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}

int configure_server_ssl(
    mbedtls_ssl_context* ssl,
    mbedtls_ssl_config* conf,
    mbedtls_ssl_cache_context* cache,
    mbedtls_ctr_drbg_context* ctr_drbg,
    mbedtls_x509_crt* server_cert,
    mbedtls_pk_context* pkey)
{
    int ret = 1;
    // Generate certificate
    // Source: https://github.com/Mbed-TLS/mbedtls/blob/b51f3da3549034818ea5e7b66695a44c65454cbc/programs/ssl/ssl_server.c
    //ret = mbedtls_x509_crt_parse(&server_cert, (const unsigned char *) mbedtls_test_srv_crt,
    //                           mbedtls_test_srv_crt_len);
    //mbedtls_x509_crt* server_cert,
    const char* path = "cert.pem";
    ret = mbedtls_x509_crt_parse_file(server_cert, path); 	
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    //ret =  mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
    //                                mbedtls_test_srv_key_len, NULL, 0,
    //                          mbedtls_ctr_drbg_random, &ctr_drbg);
    ret = mbedtls_pk_parse_keyfile(pkey, "key.pem", NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    //mbedtls_printf(" ok\n");
    // ---------------------// 
    printf(TLS_SERVER "\nSetting up the SSL configuration....\n");
    if ((ret = mbedtls_ssl_config_defaults(
             conf,
             MBEDTLS_SSL_IS_SERVER,
             MBEDTLS_SSL_TRANSPORT_STREAM,
             MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        printf(
            TLS_SERVER
            "failed\n  ! mbedtls_ssl_config_defaults returned failed %d\n",
            ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ssl_conf_dbg(conf, my_debug, stdout);
    mbedtls_ssl_conf_session_cache(
        conf, cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);

    // need to set authmode mode to OPTIONAL for requesting client certificate
    //mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    //mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);
    mbedtls_ssl_conf_ca_chain(conf, server_cert->next, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(conf, server_cert, pkey)) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n",
            ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(ssl, conf)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }
    ret = 0;
exit:
    fflush(stdout);
    return ret;
}

void extract_request_data(
			  unsigned char* buf,
			  std::string& method,
			  std::string& path,
			  std::string& content_type,
			  int& content_length,
			  std::string& data
			  ){
  std::string str;
  // Extract request data
  str.clear(); // Test clearing string befor use
  str = std::string((char*)buf, TLS_BUFFER_SIZE);  // Here program crash

  // Extract METHOD
  method = str.substr(0, str.find(" "));
  str.erase(0, method.length()+1);

  // Extract PATH
  path = str.substr(0, str.find(" "));
  str.erase(0, path.length()+1);

  //prot = str.substr(0,str.find('\n'));
  str.erase(0,str.find('\n')+1); // remove protocol

  str.erase(0,str.find('\n')+1);// Remove host info

  content_type = str.substr(0,str.find('\n'));
  content_type.erase(0,str.find(": ")+1);// Remove type declaration
  str.erase(0,str.find('\n')+1);
	
  // Extract Content length
  content_length = std::stoi(str.substr(str.find("Content-Length")+sizeof("Content-Length "), str.find("\n")));
	
  // Extract data if any
  if (str.length()>0){
    data = str.substr(str.find("\n\r\n")+3,str.length());
  }

  /*
  printf("New method extracted request data:\n");
  printf("Method:%s\n", method.c_str());
  printf("Path:%s\n", path.c_str());
  printf("Content-Type:%s\n", content_type.c_str());
  printf("Content-Length:%d\n", content_length);
  printf("Data:%s\n", data.c_str());
  printf("\n");
  */
}

void dump_json(json dict){
  std::string json_string = dict.dump(4);
  printf("Json data:\n%s\n", json_string.c_str());
}

void extract_data_values(
			 json entry,
			 std::string& id,
			 std::string& value,
			 std::string& iv,
			 int& len)
{
  id = entry["id"];
  value = entry["data"]["value"];
  iv = entry["data"]["iv"];
  len = entry["data"]["len"];
}

void print_data(std::string id, std::string value, std::string iv, int len){
      printf("Id:%s\n", id.c_str());
      printf("Data:%s\n", value.c_str());
      printf("Data len:%d\n", len);
      printf("iv_str:%s\n", iv.c_str());
}

void print_all_data(){
  std::string id;
  std::string value;

  printf("Print Content of DATA:\n");
  int N = DATA.size();
  for (int i=1; i<=N; i++) {
    id = std::to_string(i);
    value = DATA[id];
    printf("User:%s\n", id.c_str());
    printf("Value:%s\n", value.c_str());
    printf("----\n");
  }
  printf("Number of items in DATA:%d\n", DATA.size());
  printf("-- All Data printed --\n");

}

long compute_sum(json data){
  long sum = 0;
  std::string id;
  std::string value;

  int N = data.size();
  for (int i=1; i<=N; i++) {
    id = std::to_string(i);
    value = DATA[id];
    sum+=std::stoi(value.c_str());
  }
  return sum;
}

void get_lsf_data(double* x, double* y){
    // Format data
    int N = DATA.size();
    std::string id;
    std::string value;
    std::size_t delimiter_index;
    char delimiter = ',';
    char end_char = ')';
    std::string tmp;

    for (int i=1; i<=N; i++) {
      id = std::to_string(i);
      value = DATA[id];

      value[value.find(end_char)] = '\0'; // Remove last paranthesis
	    
      delimiter_index = value.find(delimiter);

      // Extract x, ignore begining paranthesis
      tmp = value.substr(1, delimiter_index);
      x[i-1]=atof(tmp.c_str());;

      // Extract y, ignore delimiter and initial space
      tmp = value.substr(delimiter_index+2);
      y[i-1]=atof(tmp.c_str());;
    }
}

svm_model *svm_model;
int handle_get_request(std::string path, std::string& response){
  response = std::string("200 GET request received");

  unsigned char encrypted_result[MBEDTLS_MPI_MAX_SIZE];
  int to_encrypt_len;

  if (path=="/sum"){
    long sum = compute_sum(DATA);
    std::string result = std::to_string(sum);

    response = result;
  } else if (path == "/hist"){
    int n_bins = 10;
    int min_v = 0;
    int max_v = 101;
    gsl_histogram * h = gsl_histogram_alloc (n_bins);
    gsl_histogram_set_ranges_uniform (h, min_v, max_v);

    int N = DATA.size();
    std::string value;
    for (int i=1; i<=N; i++){
      value = DATA[std::to_string(i)];
      gsl_histogram_increment(h, stoi(value));
    }

    std::string result = "";
    for (int i=0; i<n_bins; i++){
      result.append(std::to_string(int(h->bin[i])));
      if (i<n_bins-1){
      	result.append(",");
      }
    }
    response = result;

  } else if (path == "/lsf"){
    // Format data
    int N = DATA.size();
    std::string id;
    std::string value;
    
    double x[N];
    double y[N];
    std::string result;

    get_lsf_data(x, y);

    double c0, c1, cov00, cov01, cov11, sumsq;
    int res = gsl_fit_linear(x, 1, y, 1, N, &c0, &c1, &cov00, &cov01, &cov11, &sumsq);

    result = std::to_string(c0);
    result+=",";
    result+=std::to_string(c1);

    response = result;

  } else if (path == "/svm"){
  
    //char tst_data[] = "2 1:-0.860107 2:-0.111111 3:-1 4:-1 5:-1 6:-0.777778 7:-1 8:-0.555556 9:-1 10:-1 \n";

    int *prediction = (int*)malloc(1 * sizeof(int));
    int N = DATA.size();
    std::string id;
    std::string value;
    int predictions[N];
    for (int i=1; i<=N; i++) {
      init(svm_model);
      prediction[0]=-1;
      id = std::to_string(i);
      value = DATA[id];
      predict((char*)value.c_str(), prediction);
      predictions[i-1]=prediction[0];
      svm_clean();
    }

    std::string result;
    for (int i=1; i<=N; i++) {
        result.push_back(predictions[i-1] + '0');
	if (i!=N)
	  result.push_back(',');
    }

    response = result;

    free(prediction);
    
  } else if (path == "/clear"){
    DATA.clear();
  }
   
  return 0;
}

int handle_post_request(std::string path, std::string data, std::string& response){
  response = "HTTP/1.0 200 OK\n\rContent-Type: text/html\n\r\n\rPOST request recieved";

  const int KEY_LEN = 32;
  
  if(path=="/data"){
    json data_dict = json::parse(data.c_str());
    json entry;
    int n = data_dict.size();

    std::string id;
    std::string value;
    
    for (int i=0; i<n; i++){
      entry = data_dict[i];

      id = entry["id"];
      value = entry["data"]["value"];

      DATA[id] = value;
      //std::string stored = DATA[id];
      //printf("Stored value for user %s:%s\n", id.c_str(), stored.c_str());
    }

  }
  else{
    printf("Unknown path type recieved\n");
    response = "HTTP/1.0 404 Not Found\n\rContent-Type: text/html\n\r\n\rPOST Path not defined";
  }
  
  return 0;
}

// This routine was created to demonstrate a simple communication scenario
// between a TLS client and an TLS server. In a real TLS server app, you
// definitely will have to do more that just receiving a single message
// from a client.
int handle_communication_until_done(
    mbedtls_ssl_context* ssl,
    mbedtls_net_context* listen_fd,
    mbedtls_net_context* client_fd,
    bool keep_server_up)
{
    int ret = 0;
    int len = 0;

    std::string str;
    std::string method;
    std::string path;
    std::string prot;
    std::string content_type;
    int content_length;
    std::string data;

    std::string response;
    unsigned char buf[TLS_BUFFER_SIZE];
  

waiting_for_connection_request:

    if (ret != 0 &&
        // ignore EOF errors, which can be caused due to Load Balancers
        // or health checks
        ret != MBEDTLS_ERR_SSL_CONN_EOF)
    {
        mbedtls_strerror(ret, error_buf, MAX_ERROR_BUFF_SIZE);
        printf("Last error was: %d - %s\n", ret, error_buf);
    }

    // reset ssl setup and client_fd to prepare for the new TLS connection
    mbedtls_net_free(client_fd);
    mbedtls_ssl_session_reset(ssl);

    if (ret != MBEDTLS_ERR_SSL_CONN_EOF)
      if (DEBUG)
        printf(TLS_SERVER "Waiting for a client connection request...\n");

    if ((ret = mbedtls_net_accept(listen_fd, client_fd, NULL, 0, NULL)) != 0)
    {
        char errbuf[512];
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        printf(
            TLS_SERVER " failed\n  ! mbedtls_net_accept returned %d \n %s\n",
            ret,
            errbuf);
        goto done;
    }

    // set up bio callbacks
    mbedtls_ssl_set_bio(
        ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0)
    {
        // Load balancer health-check pings can cause EOF errors
        // Ignore the error, and wait for client to send request
        if (ret == MBEDTLS_ERR_SSL_CONN_EOF)
        {
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed\n  ! mbedtls_ssl_handshake returned -0x%x\n",
                -ret);
            goto done;
        }
    }

    if (DEBUG)
      printf(TLS_SERVER "mbedtls_ssl_handshake done successfully\n");

    // read client's request
    if (DEBUG)
      printf(TLS_SERVER "<---- Read from client:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(ssl, buf, (size_t)len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf(TLS_SERVER "connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    printf(TLS_SERVER "connection was reset by peer\n");
                    break;

                default:
                    printf(
                        TLS_SERVER "mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }
            break;
        }

        len = ret;
	// START OF HANDLING SERVER REQUEST
	if (DEBUG)
	  printf(TLS_SERVER "%d bytes received from client:\n", len);

	/*
	printf(TLS_SERVER " Printing incomming request data:\n");
	int i=0;
	while (buf[i]!='\0'){
	  //printf("%02x ", buf[i]);
	  printf("%c", buf[i++]);
	}
	printf("\n");
	*/

	// Extract request data
	extract_request_data(buf, method, path, content_type, content_length, data);
	if (DEBUG){
	  // Print extracted data
	  printf("Extracted request data:\n");
	  printf("Method:%s\n", method.c_str());
	  printf("Path:%s\n", path.c_str());
	  printf("Content-Type:%s\n", content_type.c_str());
	  printf("Content-Length:%d\n", content_length);
	  printf("Data:%s\n", data.c_str());
	}

	// Init default response
	response = "HTTP/1.0 200 OK\n\rContent-Type: text/html\n\r\n\rServer is up";
	if (method=="GET"){
	  handle_get_request(path, response);
	}
	else if(method=="POST"){
	  handle_post_request(path, data, response);
	}
	else{
	  printf("Unknown request type recieved");
	}

	break;
    } while (1);

    // Write a response back to the client
    if (DEBUG){
      printf(TLS_SERVER "-----> Write to client:\n");
      printf("Buffer size:%d\n", sizeof(buf));
      printf("Writing len:%d\n", len);
    }
    len = snprintf((char*)buf, sizeof(buf) - 1, response.c_str());

    if (DEBUG){
      printf("Send response:%s\n", (char*)buf);
      printf("New writing len:%d\n", len);
    }

    while ((ret = mbedtls_ssl_write(ssl, buf, (size_t)len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            printf(TLS_SERVER "failed\n  ! peer closed the connection\n\n");
            goto waiting_for_connection_request;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed\n  ! mbedtls_ssl_write returned %d\n\n",
                ret);
            goto done;
        }
    }

    len = ret;
    if (DEBUG){
      printf(TLS_SERVER "%d bytes written to client\n\n", len);
      printf(TLS_SERVER "Closing the connection...\n");
    }
    while ((ret = mbedtls_ssl_close_notify(ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(
                TLS_SERVER "failed! mbedtls_ssl_close_notify returned %d\n\n",
                ret);
            goto waiting_for_connection_request;
        }
    }

    ret = 0;

    if (keep_server_up)
        goto waiting_for_connection_request;

done:
    return ret;
}

int set_up_tls_server(char* server_port, bool keep_server_up)
{
    int ret = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context pkey;
    mbedtls_ssl_cache_context cache;
    mbedtls_net_context listen_fd, client_fd;
    const char* pers = "tls_server";

    // Init SVM Model
    svm_model = svm_load_model_from_string(breast_cancer_model);
    
    // init mbedtls objects
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ssl_cache_init(&cache);
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf(
        TLS_SERVER "Setup the listening TCP socket on SERVER_IP= [%s] "
                   "server_port = [%s]\n",
        SERVER_IP,
        server_port);
    if ((ret = mbedtls_net_bind(
             &listen_fd, SERVER_IP, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_bind returned %d\n", ret);
        goto exit;
    }

    printf(
        TLS_SERVER "mbedtls_net_bind returned successfully. (listen_fd = %d)\n",
        listen_fd.fd);

    printf(TLS_SERVER "Seeding the random number generator (RNG)\n");
    if ((ret = mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             (const unsigned char*)pers,
             strlen(pers))) != 0)
    {
        printf(
            TLS_SERVER "failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // Configure server SSL settings
    ret = configure_server_ssl(
        &ssl, &conf, &cache, &ctr_drbg, &server_cert, &pkey);
    if (ret != 0)
    {
        printf(TLS_SERVER "failed\n  ! mbedtls_net_connect returned %d\n", ret);
        goto exit;
    }
    //printf("configure_server_ssl success!\n");

    // handle communication
    ret = handle_communication_until_done(
        &ssl, &listen_fd, &client_fd, keep_server_up);
    if (ret != 0)
    {
        printf(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:

    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        printf(TLS_SERVER "Last error was: %d - %s\n\n", ret, error_buf);
    }

    // free resource
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&server_cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cache_free(&cache);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    fflush(stdout);
    return (ret);
}

int main(int argc, char **argv){
  printf("Non secure server running!\n");
  char server_port[] = "12342";
  bool keep_server_up = true;
  set_up_tls_server(server_port, keep_server_up);
  return 0;
}
