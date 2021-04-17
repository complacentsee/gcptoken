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

#include <Arduino.h>

class gcptoken {
 private:
    const char *_service_kid; 
    const char *_target_audience; 
    const char *_audience = "https://oauth2.googleapis.com/token";
    const char *_service_account;
    const char *_service_private_key_str;
    const char *_servicetokenid = "id_token";
    const char *_scopetokenid = "access_token";
    const char *_ROOTCA;

    char * _serviceJWT;
    char * _servicetoken;

    int _service_token_life = 3600;
    long long int _service_jwt_exp_secs = 0;
    long long int _service_token_exp_secs = 0;      //DO I ACTUALLY NEED THIS?
    unsigned long _service_exp_millis = 0;

    //Scoped Token Private Variables
    char * _scopedJWT;
    char * _scopedToken;

    int _scoped_token_life = 3600;
    long long int _scoped_jwt_exp_secs = 0;
    long long int _scoped_token_exp_secs = 0;      //DO I ACTUALLY NEED THIS?
    unsigned long _scoped_exp_millis = 0;

    const char * Host = "oauth2.googleapis.com";                // Host for google OAuth2.0 servers
    const char * Path = "/token";                               // OAuth2.0 token API path
    int Port = 443;                                             // For HTTPS 443.

    //Private functions to handle creating a service JWT. This JWT will be exchanged for a usable token. 
    String base64_encode(const unsigned char *bytes_to_encode,
                     unsigned int in_len);
    String base64_encode(String str);

 public:
 //Constructors for object
  gcptoken();                                                                         
  gcptoken(const char *service_kid, const char *target_audience, 
        const char *service_account, const char *service_private_key_str, const char *ROOTCA);   

  gcptoken &setServiceKid(const char *service_kid);                                   
  gcptoken &setTargetAudience(const char *target_audience);                           
  gcptoken &setServiceAccount(const char *service_account);                           
  gcptoken &setPrivateKey(const char *service_private_key_str);
  gcptoken &setROOTCA(const char *ROOTCA);                        


  long long int getServiceJwtExpSecs();                                               
  long long int getScopedJwtExpSecs();                                                

//NOT SURE IF THESE TWO PROVIDE VALUE
  void setServiceJwtExpSecs(long long int exp_in_secs);                               
  void setScopedJwtExpSecs(long long int exp_in_secs);                                

  void setServiceTokenExpSecs(long long int exp_in_secs);                             
  void setScopedTokenExpSecs(long long int exp_in_secs);                              

//Create JWTs. JWT will be exchanged for
  char * createJWT(String payload, char * buffer);                               
  char * createServiceJWT(long long int time);                                        
  char * createServiceJWT(long long int time, int jwtlife);                           
  char * createScopedJWT(String scope, long long int time);                           
  char * createScopedJWT(String scope, long long int time, int jwtlife);              

  char * requestToken(char * JWT, const char * tokenid, char * buffer);    
  char * requestServiceToken();                                                       
  char * requestScopedToken();                                                        

//THESE NEED TO BE UPDATED WITH AUTO-REFRESH
  char * getServiceToken();                                                           
  char * getServiceToken(long long int time);                                         
  char * getScopedToken();                                                           
  char * getScopedToken(String scope, long long int time);                            

  void setServiceToken(char * token);                                                                                                          
  void setScopedToken(char * token);                                                  

};