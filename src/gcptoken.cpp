/******************************************************************************
 * Copyright 2021 complacentsee
 * Licensed under the GNU Lesser General Public License v2.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/

#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "gcptoken.h"
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// copied from Google CloudIoTCore
// base64_encode copied from https://github.com/ReneNyffenegger/cpp-base64
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

String gcptoken::base64_encode(const unsigned char *bytes_to_encode,
                     unsigned int in_len) {
  String ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++) {
        ret += base64_chars[char_array_4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++) {
      char_array_3[j] = '\0';
    }

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++) {
      ret += base64_chars[char_array_4[j]];
    }
  }

  return ret;
}

String gcptoken::base64_encode(String str) {
  return base64_encode((const unsigned char *)str.c_str(), str.length());
}

gcptoken::gcptoken() {}

gcptoken::gcptoken(const char *service_kid, const char *target_audience, 
        const char *service_account, const char *service_private_key_str,
        const char *ROOTCA){
  setServiceKid(service_kid);
  setTargetAudience(target_audience);
  setServiceAccount(service_account);
  setPrivateKey(service_private_key_str);
  setROOTCA(ROOTCA);
  _serviceJWT = (char*)malloc(sizeof(char)*1);
  _scopedJWT = (char*)malloc(sizeof(char)*1);
  _servicetoken= (char*)malloc(sizeof(char)*1);
  _scopedToken= (char*)malloc(sizeof(char)*1);
}

gcptoken &gcptoken::setServiceKid(const char *service_kid) {
  this->_service_kid = service_kid;
  return *this;
}

gcptoken &gcptoken::setTargetAudience(const char *target_audience) {
  this->_target_audience = target_audience;
  return *this;
}

gcptoken &gcptoken::setServiceAccount(const char *service_account) {
  this->_service_account = service_account;
  return *this;
}

gcptoken &gcptoken::setPrivateKey(const char *service_private_key_str) {
  this->_service_private_key_str = service_private_key_str;
  return *this;
}

gcptoken &gcptoken::setROOTCA(const char *ROOTCA) {
  this->_ROOTCA = ROOTCA;
  return *this;
}

char * gcptoken::createJWT(String scope, char * buffer){
  mbedtls_pk_context context;
  mbedtls_pk_init(&context);   

// header creation
  String header = String("{\"alg\":\"RS256\"") 
    + ",\"typ\":\"JWT\""
    + "}";

  // base64 encode {header}.{payload}, and combine
  String header_base64 = base64_encode(header);
  String payload_base64 = base64_encode(scope);
  String message = header_base64 + "." + payload_base64;

  int rc = mbedtls_pk_parse_key(&context,
                                (const unsigned char *)_service_private_key_str,
                                strlen(_service_private_key_str)+1,
                                nullptr,
                                0);
  //
    uint8_t hash[32];
    rc = mbedtls_md(
                    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    (const uint8_t *)message.c_str(), 
                    message.length(), 
                    hash);
    

    size_t sig_len = mbedtls_pk_get_len(&context);
    uint8_t *sig=(uint8_t *)calloc(sig_len,1);

    mbedtls_pk_sign(
        &context,
        MBEDTLS_MD_SHA256,
        hash,
        sizeof(hash),
        sig,
        &sig_len,
        NULL,NULL);
    
    String signiture = base64_encode((const unsigned char *)sig, sig_len);

    //Free alocated memory
    free(sig);
    mbedtls_pk_free(&context);

    message = message + "." + signiture;
    
    char * more = (char*)realloc(buffer,sizeof(char)*(message.length()+1));
    if( more == NULL ){
      free(buffer);
      buffer = (char*)malloc(sizeof(char)*(message.length()+1));
    } else {
      buffer=more;
      sprintf(buffer, message.c_str());
    }
  return buffer;
}

char * gcptoken::createServiceJWT(long long int time){
  _serviceJWT = createServiceJWT(time, 3600);
  return _serviceJWT;
}

char * gcptoken::createServiceJWT(long long int time, int jwtlife){
  String payload = String("{")
    + "\"iss\":\"" +              _service_account    + "\""  
    + ",\"sub\":\"" +             _service_account    + "\"" 
    + ",\"aud\":\"" +             _audience           + "\"" 
    + ",\"target_audience\":\"" + _target_audience    + "\""    
    + ",\"iat\":" +               (int) (time)
    + ",\"exp\":" +               (int) (time + jwtlife)
    + "}";
    
  _service_token_life = jwtlife;
  _service_jwt_exp_secs = time + jwtlife;
  _serviceJWT=createJWT(payload, _serviceJWT);
  return _serviceJWT;
}

char * gcptoken::createScopedJWT(String scope, long long int time){
  _scopedJWT = createScopedJWT(scope, time, 3600);
  return _scopedJWT;
}

char * gcptoken::createScopedJWT(String scope, long long int time, int jwtlife){
  String payload = String("{")
    + "\"iss\":\"" +         _service_account     + "\""  
    + ",\"sub\":\"" +        _service_account     + "\"" 
    + ",\"aud\":\"" +        _audience            + "\"" 
    + ",\"scope\":\"" +      scope                + "\""    
    + ",\"iat\":" +          (int) (time)
    + ",\"exp\":" +          (int) (time + jwtlife)
    + "}";
  _scoped_token_life = jwtlife;
  _scoped_jwt_exp_secs = time + jwtlife;
  _scopedJWT = createJWT(payload, _scopedJWT);;
  return _scopedJWT;
}

void gcptoken::setServiceJwtExpSecs(long long int exp_in_secs) {
  _service_jwt_exp_secs =  exp_in_secs;
  return ;
}

void gcptoken::setScopedJwtExpSecs(long long int exp_in_secs) {
  _scoped_jwt_exp_secs =  exp_in_secs;
  return ;
}

void gcptoken::setServiceTokenExpSecs(long long int exp_in_secs) {
  _service_token_exp_secs =  exp_in_secs;
  return ;
}

void gcptoken::setScopedTokenExpSecs(long long int exp_in_secs) {
  _scoped_token_exp_secs =  exp_in_secs;
  return ;
}

long long int gcptoken::getServiceJwtExpSecs() {
  return _service_jwt_exp_secs;
}

long long int gcptoken::getScopedJwtExpSecs() {
  return _scoped_jwt_exp_secs;
}

char * gcptoken::requestToken(char * JWT, const char * tokenid, char * buffer){
  WiFiClientSecure client;
  String ret;
  int status = 0;
  Serial.println("Connecting to: " + String(Host));

  if (client.connect(Host, Port)) {
    client.setCertificate(_ROOTCA);
    HTTPClient https; 
    String req = String("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=") + JWT;
      if (https.begin(client, Host, Port, Path, true)) {
          https.addHeader("Content-Type", "application/x-www-form-urlencoded");
          https.addHeader("Host", String(Host));
          https.addHeader("Content-Length", String(req.length()));
          int  httpCode = https.POST(req);
          if (httpCode > 0) {
            // HTTP header has been sent and Server response header has been handled
            Serial.printf("[HTTPS] code: %d\n", httpCode);
            if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
              String payload = https.getString();
              //Serial.println(payload);  //Uncomment this line if you would like to print the token. 
              DynamicJsonDocument http_payload(https.getSize()+floor(0.1*https.getSize()));
              deserializeJson(http_payload, payload);
              if(http_payload.containsKey(tokenid)){
                ret = ret + http_payload[tokenid].as<String>();
                status = 0;
              }
            }
          } else {
            Serial.println("[HTTPS] failed, error: " + String(httpCode) + " = " +  https.errorToString(httpCode).c_str());
            status = 1;
          }
          https.end();
        } else {
          Serial.printf("[HTTPS] Unable to connect\n");
          status = 2;
        }
  }
  client.stop();

  char * more = (char*)realloc(buffer,sizeof(char)*(ret.length()+1));
  if( more == NULL ){
    free(buffer);
    buffer = (char*)malloc(sizeof(char)*(ret.length()+1));
  } else {
    buffer=more;
    sprintf(buffer, ret.c_str());
  }
  return buffer;
}

char * gcptoken::requestServiceToken(){
  _servicetoken = requestToken(_serviceJWT, _servicetokenid, _servicetoken);
  _service_token_exp_secs = _service_jwt_exp_secs;
  _service_exp_millis = millis() + _service_token_life * 1000;
  return _servicetoken;
}

char * gcptoken::requestScopedToken(){
  _scopedToken = requestToken(_scopedJWT, _scopetokenid, _scopedToken);
  _scoped_token_exp_secs = _scoped_jwt_exp_secs;
  _scoped_exp_millis = millis() + _scoped_token_life * 1000;
  return _scopedToken;
}

char * gcptoken::getServiceToken(){
  return _servicetoken;
} 

char * gcptoken::getServiceToken(long long int time){
  if((millis() >= _service_exp_millis) || (time >= _service_token_exp_secs)){
    createServiceJWT(time);
    requestServiceToken();
  }
  return _servicetoken;
} 

void gcptoken::setServiceToken(char * token){
  _servicetoken = token;
}

char * gcptoken::getScopedToken(){
  return _scopedToken;
} 

char * gcptoken::getScopedToken(String scope, long long int time){
  if((millis() >= _scoped_exp_millis) || (time >= _scoped_token_exp_secs)){
    createScopedJWT(scope, time);
    requestScopedToken();
  }
  return _scopedToken;
} 

void gcptoken::setScopedToken(char * token){
  _scopedToken = token;
}