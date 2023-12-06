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
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "../../common/mbedtls_utility.h"

#include "string"

// For GSL Histograms and LSF
#include <gsl_histogram.h>
#include <fit/gsl_fit.h>

// For libSvm:
#include "../../libsvm/svm.h"
#include "../../libsvm/svm.cpp"
#include "../../libsvm/models.c"
#include "../../libsvm/data.c"
#include "../../libsvm/svm-predict-lib.c"

//#include "../../common/cpp-base64/base64.h"

// DEBUG variable to enable/disable printouts
bool DEBUG = false;
//bool DEBUG = true;

// Json parsing
#include "../../common/nlohmann/json.hpp"
using json = nlohmann::json;
json KEYS;
json DATA;

extern "C"
{
    int set_up_tls_server(char* server_port, bool keep_server_up);
};

#define MAX_ERROR_BUFF_SIZE 256
char error_buf[MAX_ERROR_BUFF_SIZE];
int TLS_BUFFER_SIZE = 16384;// Max size for TLS packet

const unsigned char result_key[]="-----BEGIN PUBLIC KEY-----\n"		\
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsENDktzQ7UR1BxSlImFh\n"	\
  "LAcsViOHTi5D0wD2SvRl/esM+h+ytBUC8jOgINjtmwA5wdA/42ffpEmK5B0La1Fi\n"	\
  "Pa5K5mvLe2WplcyzgMGZ2mZd2z+BUreLOvDd2zedCWNg8vwD91CeApLeeLe47q/2\n"	\
  "6YY3jyxqwRrirn9pvSpfFj1AQSQa01Sjhbnh4lmbpoB2CraUCfx4wT5sPC15hb1L\n"	\
  "NLY3cDnmbVP+Uw8valvz8ofIrMFaSxa03SyAkpRhmQdGOwDqcNKvXAgU08jcg/1F\n"	\
  "vmst1T7ljNgt02YcOv743iv79xfetD0i+i6D0FlQjoNKqLM6swGlXesWWO5BKhU7\n"	\
  "QwIDAQAB\n"								\
  "-----END PUBLIC KEY-----\n";

  // BASE64 decoding:
//Source: https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";
typedef unsigned char BYTE;

static inline bool is_base64(BYTE c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(BYTE const* buf, unsigned int bufLen) {
  std::string ret;
  int i = 0;
  int j = 0;
  BYTE char_array_3[3];
  BYTE char_array_4[4];
  //printf("Encoding... len=%d\n", bufLen);
  //printf("buffer:%s\n", buf);
  
  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  BYTE char_array_4[4], char_array_3[3];
  std::vector<BYTE> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
          ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}


// Source https://mbed-tls.readthedocs.io/en/latest/kb/how-to/encrypt-and-decrypt-with-rsa/
int encrypt_result(const unsigned char* key, unsigned char* to_encrypt, int to_encrypt_len, unsigned char* buf){
  int ret = 0;
  
  // Adding random number generator
  // Source: https://mbed-tls.readthedocs.io/en/latest/kb/how-to/add-a-random-generator/

  // Entropy source (this should probably move to something like main
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init( &entropy );
  // Is done in set_up_tls_server, check if possible to reuse
  // ----------------------------//
  
  // The actual random generator
  mbedtls_ctr_drbg_context ctr_drbg;
  char *personalization = "my_app_specific_string"; // Protects against lack of entropy

  mbedtls_ctr_drbg_init( &ctr_drbg );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
			       (const unsigned char *) personalization,
			       strlen( personalization ) );
  if( ret != 0 )
    {
      // ERROR HANDLING CODE FOR YOUR APP
      printf("Error generating randomization\n");
    }
  // --------------------------------------- //
  
  // Init public key context
  mbedtls_pk_context pk;
  mbedtls_pk_init( &pk );

  /*
   * Read the RSA public key
   */
  // Change from source above to use variable instead
  //if( ( ret = mbedtls_pk_parse_public_keyfile( &pk, "our-key.pub" ) ) != 0 )
  //printf("Size of key:%d\n", sizeof(result_key));
  //printf("Size of key:%d\n", strlen((char*)key));
  int key_size = strlen((char*)key)+1;// +1 to include null terminator
  if( ( ret = mbedtls_pk_parse_public_key( &pk, key, key_size) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_pk_parse_public_key returned -0x%04x\n", -ret );
      //goto exit;
    }

  // Encrypt the data
  size_t olen = 0;

  /*
   * Calculate the RSA encryption of the data.
   */
  int buffer_size = MBEDTLS_MPI_MAX_SIZE;
  if( ( ret = mbedtls_pk_encrypt( &pk, to_encrypt, to_encrypt_len,
				  buf, &olen, buffer_size,
				  mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
      printf( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
      printf("Error code:%d\n", ret);
      //goto exit;
    }

  //free(personalization);
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);


  return ret;    
}


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
  // while (data[i++]!='\0'){
  //   printf("%02x ", data[i]);
  // }
  // printf("\n");
}


void encrypt_aes_data(){
  mbedtls_aes_context aes;
  mbedtls_aes_context aes2;
  mbedtls_aes_init(&aes);
  mbedtls_aes_init(&aes2);
  const int KEY_LEN=32;

  unsigned char key[KEY_LEN+1] = "my secret key for encryption1234"; // +1 to accommodate for the null terminator
  //const unsigned char* key = "my secret key for encryption1234";
  unsigned char iv[17] = "This is an IV456";
  unsigned char iv_dec[17] = "This is an IV456";

  unsigned char message [128] = "s012345678901234567890123456789\0";
  unsigned char cipher[128];
  unsigned char decrypted[128] = "\0";

  size_t input_len = 32;
  size_t output_len =32;

  int status;
  //key = (unsigned char*)"my secret key";
  //input = "my secret message"
  printf("Len of message:%d\n",strlen((char*)message) );
  status = mbedtls_aes_setkey_enc( &aes, key, 256 );
  printf("Status set enc key:%d\n", status);
  status = mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, input_len, iv, message, cipher );
// mbedtls_aes_crypt_ofb 	( 	mbedtls_aes_context *  	ctx,
// 		size_t  	length,
// 		size_t *  	iv_off,
// 		unsigned char  	iv[16],
// 		const unsigned char *  	input,
// 		unsigned char *  	output 
// 	) 		
  printf("Status encryption:%d\n", status);
  //printf("Message:%s\n", message);
  printf("Encrypted:");
  print_hex(cipher, 32);
  printf("\n");

  
  status = mbedtls_aes_setkey_dec( &aes2, key, 256 );
  printf("Status set dec key:%d\n", status);
  status = mbedtls_aes_crypt_cbc( &aes2, MBEDTLS_AES_DECRYPT, output_len, iv_dec, cipher, decrypted);
  printf("Decryption status:%d\n", status);
  printf("Decrypted:%s\n", decrypted);
  printf("MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH=%d\n",MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);
  printf("Len decrypted:%d\n", strlen((char*)decrypted));
}

int decrypt_aes_data(
		      unsigned char* key,
		      unsigned char* iv,
		      size_t message_len,
		      unsigned char* cipher,
		      unsigned char* decrypted
		      ){
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  const int KEY_LEN=32;
  const int MAX_DATA_LEN=96;
  int status;
  //status = mbedtls_aes_setkey_enc( &aes, key, 256 );
  //  printf("Status set enc key:%d\n", status);
  
  status = mbedtls_aes_setkey_dec( &aes, key, 256 );
  //printf("Status set dec key:%d\n", status);
  
  // mbedtls_aes_crypt_ofb 	( 	mbedtls_aes_context *  	ctx,
// 		size_t  	length,
// 		size_t *  	iv_off,
// 		unsigned char  	iv[16],
// 		const unsigned char *  	input,
// 		unsigned char *  	output 
// 	) 		
  //printf("Status encryption:%d\n", status);

  // status = mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, KEY_LEN, iv, cipher, decrypted);
  status = mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, message_len, iv, cipher, decrypted);
  // printf("Decryption1 status:%d\n", status);
  // printf("Decrypted1:%s\n", decrypted);
  int end = message_len-(int)decrypted[message_len-1];
  // printf("Last byte of decrypted:%d\n", decrypted[message_len-1]);
  // printf("Message length:%d\n",message_len);
  // printf("Length of original message:%d\n", end);
  decrypted[end+1] = '\0';
  //status = mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, MAX_DATA_LEN, iv, cipher[16], decrypted);
  //printf("Decryption2 status:%d\n", status);
  //printf("Decrypted2:%s\n", decrypted);
  //decrypted[message_len+1] = '\0';
  //printf("Decrypted:%s\n", decrypted);

  if (status!=0)
    printf("MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH=%d\n",MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH);

  return status;
}

int cert_verify_callback(
    void* data,
    mbedtls_x509_crt* crt,
    int depth,
    uint32_t* flags);

#define SERVER_IP "0.0.0.0"

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

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
    oe_result_t result = OE_FAILURE;

    printf(TLS_SERVER "Generating the certificate and private key\n");
    result = generate_certificate_and_pkey(server_cert, pkey);
    if (result != OE_OK)
    {
        printf(TLS_SERVER "failed with %s\n", oe_result_str(result));
        goto exit;
    }

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
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(conf, cert_verify_callback, NULL);
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
  // for (auto& [key, v] : DATA.items()) {
  //   id = std::string(key);
  //   value = std::string(v);
  //   printf("User:%s\n", id.c_str());
  //   printf("Value:%s\n", value.c_str());
  //   printf("----\n");
  // }
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

unsigned char* load_stored_key(std::string id){
  std::string stored_key = KEYS[id];
  std::vector<BYTE> decoded_key;
  //unsigned char* key;
  // decode b64 key:
  decoded_key = base64_decode(stored_key);
  return &decoded_key[0];
}

long compute_sum(json data){
  long sum = 0;
  std::string id;
  std::string value;

  int N = data.size();
  for (int i=1; i<=N; i++) {
    id = std::to_string(i);
    //printf("Id:%s\n", id.c_str());
    value = DATA[id];
    //printf("Value:%s\n", value.c_str());
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


svm_model* svm_model;
int handle_get_request(std::string path, std::string& response){
  response = std::string("200 GET request received");

  unsigned char encrypted_result[MBEDTLS_MPI_MAX_SIZE];
  int to_encrypt_len;

  if (path=="/sum"){
    long sum = compute_sum(DATA);
    std::string result = std::to_string(sum);

    to_encrypt_len = strlen(result.c_str());
    encrypt_result(result_key, (unsigned char*)result.c_str(), to_encrypt_len, encrypted_result);
    
    response = base64_encode(encrypted_result, 256);
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
    
    to_encrypt_len = strlen(result.c_str());
    encrypt_result(result_key, (unsigned char*)result.c_str(), to_encrypt_len, encrypted_result);
    response = base64_encode(encrypted_result, 256);
      
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

    to_encrypt_len = strlen(result.c_str());
    encrypt_result(result_key, (unsigned char*)result.c_str(), to_encrypt_len, encrypted_result);
    response = base64_encode(encrypted_result, 256);
    
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
    int MAX_RSA_ENC_SIZE = 245;
    int result_len = result.length();

    int ii = 0;
    std::string to_encrypt;
    std::string encoded;

    response = "";
    while (ii<result_len){
      to_encrypt = result.substr(ii, MAX_RSA_ENC_SIZE);
      ii+=MAX_RSA_ENC_SIZE;

      // Encrypt part of result
      to_encrypt_len = strlen(to_encrypt.c_str());
      encrypt_result(result_key, (unsigned char*)to_encrypt.c_str(), to_encrypt_len, encrypted_result);
      encoded = base64_encode(encrypted_result, 256);

      response+=encoded;
      if (ii<result_len)
	response+="\n";
    }

    free(prediction);

  } else if (path == "/clear"){
    DATA.clear();
  }
  free(encrypted_result);
  if (DEBUG)
    printf("Returning from GET\n");
  return 0;
}

int handle_post_request(std::string path, std::string data, std::string& response){
  response = "HTTP/1.0 200 OK\n\rContent-Type: text/html\n\r\n\rPOST request recieved";

  const int KEY_LEN = 32;
  
  if(path=="/key"){
    const int KEY_LEN = 32;
    json data_dict = json::parse(data.c_str());

    std::vector<BYTE> decoded = base64_decode(data_dict["key"]);
    unsigned char* key  = &decoded[0];
    key[KEY_LEN] = '\0';
    
    std::string user_id = data_dict["id"];

    // Since null bytes in key makes the stored key faulty, store b64 format for now
    KEYS[user_id]=data_dict["key"];

    std::string stored_key = KEYS[user_id];
    
  } else if(path=="/data"){
    json data_dict = json::parse(data.c_str());
    json entry;
    int n = data_dict.size();
    
    const int MAX_DATA_LENGTH = 256;
    std::string id;
    std::string encoded_data;
    std::string encoded_iv;
    int data_len;
    std::vector<BYTE> decoded;
    std::vector<BYTE> decoded_iv;

    unsigned char decrypted[MAX_DATA_LENGTH];

    std::string stored_key;
    std::vector<BYTE> decoded_key;
    unsigned char* key;
    
    for (int i=0; i<n; i++){
      entry = data_dict[i];
      extract_data_values(entry, id, encoded_data, encoded_iv, data_len);
      
      // Load stored key
      stored_key = KEYS[id];

      // decode b64 key:
      decoded_key = base64_decode(stored_key);
      key  = &decoded_key[0];

      // Do same thing in subrutine
      //load_stored_key(id, key);
      //key = load_stored_key(id);
      //key[KEY_LEN]='\0';
      // print_hex(key, KEY_LEN+1);
      // printf("-------\n");

      decoded = base64_decode(encoded_data);
      decoded_iv = base64_decode(encoded_iv);

      decrypt_aes_data(key, &decoded_iv[0], data_len, &decoded[0], decrypted);

      // Store data in global variable
      DATA[id] = (char*)decrypted;
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

    if (ret != MBEDTLS_ERR_SSL_CONN_EOF){
      if (DEBUG)
        printf(TLS_SERVER "Waiting for a client connection request...\n");
    }
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
	if (DEBUG){
	  printf(TLS_SERVER "%d bytes received from client:\n", len);

	  // printf(TLS_SERVER " Printing incomming request data:\n");
	  // int i=0;
	  // while (buf[i]!='\0'){
	  //   //printf("%02x ", buf[i]);
	  //   printf("%c", buf[i++]);
	  // }
	  // printf("\n");
	}


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
    
    //len = response.length();

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

    /* Load host resolver and socket interface modules explicitly */
    if (load_oe_modules() != OE_OK)
    {
        printf(TLS_SERVER "loading required Open Enclave modules failed\n");
        goto exit;
    }

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
    oe_verifier_initialize();

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
    oe_verifier_shutdown();
    fflush(stdout);
    return (ret);
}
