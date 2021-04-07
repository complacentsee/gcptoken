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

    //Service Token Private Variables
    String _serviceJWT;
    String _servicetoken;
    int _service_token_life = 3600;
    long long int _service_jwt_exp_secs = 0;
    long long int _service_token_exp_secs = 0;      //DO I ACTUALLY NEED THIS?
    unsigned long _service_exp_millis = 0;

    //Scoped Token Private Variables
    String _scopedJWT;
    String _scopedToken;
    int _scoped_token_life = 3600;
    long long int _scoped_jwt_exp_secs = 0;
    long long int _scoped_token_exp_secs = 0;      //DO I ACTUALLY NEED THIS?
    unsigned long _scoped_exp_millis = 0;

    String Host = "oauth2.googleapis.com";                // Host for google OAuth2.0 servers
    String Path = "/token";                               // OAuth2.0 token API path
    int Port = 443;                                       // For HTTPS 443.

    const char *_gcpROOTCA =                              // GCP ROOT CA for HTTPS
        "-----BEGIN CERTIFICATE-----"
        "MIIKPDCCCSSgAwIBAgIRAJEgdT0mNbYDAgAAAAB9mBQwDQYJKoZIhvcNAQELBQAw"
        "QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET"
        "MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMDEwMDYwNjIzNThaFw0yMDEyMjkwNjIz"
        "NThaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH"
        "Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQDDAwq"
        "Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjA1b6"
        "GwgyLnW6Yf+OpXIZufL4lgH8agT6CeJpQCq6kbDhDHv2aPI8fdKaNXN7fM73PwHp"
        "RD+EobAwje09rs1nX9M/0P7FlGw3AAjg3U+Ti81ypQEdWWw04amG3ur9Cjmf7wvY"
        "rC1zBawRDSw+LxKOOvOczmTQhW9sFGi1QXAh989n27QA3OvXy2t5cc96ICnNauij"
        "zSJScXh/z9G9qWvtsnErBnsuAg3cURMdtXx/90UtbMAR8mpp5/icFnGIjXASoF64"
        "NhaqM47U28Uu93otUun266wrUt5MhRGexhohTwGUWXB/zWgmmeOK4dq3Ey1VfA8F"
        "N/NKZ4UGgiVfxZ9PAgMBAAGjggcHMIIHAzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l"
        "BAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUiz0EPWVFuMMq"
        "ZAHDOXe5rIHL9XcwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswaAYI"
        "KwYBBQUHAQEEXDBaMCsGCCsGAQUFBzABhh9odHRwOi8vb2NzcC5wa2kuZ29vZy9n"
        "dHMxbzFjb3JlMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2cvZ3NyMi9HVFMx"
        "TzEuY3J0MIIEwgYDVR0RBIIEuTCCBLWCDCouZ29vZ2xlLmNvbYINKi5hbmRyb2lk"
        "LmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYIJKi5iZG4uZGV2ghIqLmNsb3Vk"
        "Lmdvb2dsZS5jb22CGCouY3Jvd2Rzb3VyY2UuZ29vZ2xlLmNvbYIYKi5kYXRhY29t"
        "cHV0ZS5nb29nbGUuY29tggYqLmcuY2+CDiouZ2NwLmd2dDIuY29tghEqLmdjcGNk"
        "bi5ndnQxLmNvbYIKKi5nZ3BodC5jboIOKi5na2VjbmFwcHMuY26CFiouZ29vZ2xl"
        "LWFuYWx5dGljcy5jb22CCyouZ29vZ2xlLmNhggsqLmdvb2dsZS5jbIIOKi5nb29n"
        "bGUuY28uaW6CDiouZ29vZ2xlLmNvLmpwgg4qLmdvb2dsZS5jby51a4IPKi5nb29n"
        "bGUuY29tLmFygg8qLmdvb2dsZS5jb20uYXWCDyouZ29vZ2xlLmNvbS5icoIPKi5n"
        "b29nbGUuY29tLmNvgg8qLmdvb2dsZS5jb20ubXiCDyouZ29vZ2xlLmNvbS50coIP"
        "Ki5nb29nbGUuY29tLnZuggsqLmdvb2dsZS5kZYILKi5nb29nbGUuZXOCCyouZ29v"
        "Z2xlLmZyggsqLmdvb2dsZS5odYILKi5nb29nbGUuaXSCCyouZ29vZ2xlLm5sggsq"
        "Lmdvb2dsZS5wbIILKi5nb29nbGUucHSCEiouZ29vZ2xlYWRhcGlzLmNvbYIPKi5n"
        "b29nbGVhcGlzLmNughEqLmdvb2dsZWNuYXBwcy5jboIUKi5nb29nbGVjb21tZXJj"
        "ZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwqLmdzdGF0aWMuY26CDSouZ3N0YXRp"
        "Yy5jb22CEiouZ3N0YXRpY2NuYXBwcy5jboIKKi5ndnQxLmNvbYIKKi5ndnQyLmNv"
        "bYIUKi5tZXRyaWMuZ3N0YXRpYy5jb22CDCoudXJjaGluLmNvbYIQKi51cmwuZ29v"
        "Z2xlLmNvbYITKi53ZWFyLmdrZWNuYXBwcy5jboIWKi55b3V0dWJlLW5vY29va2ll"
        "LmNvbYINKi55b3V0dWJlLmNvbYIWKi55b3V0dWJlZWR1Y2F0aW9uLmNvbYIRKi55"
        "b3V0dWJla2lkcy5jb22CByoueXQuYmWCCyoueXRpbWcuY29tghphbmRyb2lkLmNs"
        "aWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5jb22CG2RldmVsb3Blci5hbmRyb2lk"
        "Lmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIEZy5jb4II"
        "Z2dwaHQuY26CDGdrZWNuYXBwcy5jboIGZ29vLmdsghRnb29nbGUtYW5hbHl0aWNz"
        "LmNvbYIKZ29vZ2xlLmNvbYIPZ29vZ2xlY25hcHBzLmNughJnb29nbGVjb21tZXJj"
        "ZS5jb22CGHNvdXJjZS5hbmRyb2lkLmdvb2dsZS5jboIKdXJjaGluLmNvbYIKd3d3"
        "Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9u"
        "LmNvbYIPeW91dHViZWtpZHMuY29tggV5dC5iZTAhBgNVHSAEGjAYMAgGBmeBDAEC"
        "AjAMBgorBgEEAdZ5AgUDMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6Ly9jcmwucGtp"
        "Lmdvb2cvR1RTMU8xY29yZS5jcmwwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgDn"
        "EvKwN34aYvuOyQxhhPHqezfLVh0RJlvz4PNL8kFUbgAAAXT8y6i5AAAEAwBHMEUC"
        "IQDqAw0LqUE2ZNHr3BlEfSjSGwdmr52bvHkg6tAH4ZriVQIgTBPdDaDPCeOWZZqH"
        "pODZMowA1uMAi514QnhFwX3dfI4AdgCyHgXMi6LNiiBOh2b5K7mKJSBna9r6cOey"
        "SVMt74uQXgAAAXT8y6izAAAEAwBHMEUCIFnALMUlQhUGXZaUCw2xWF2Ug4RGSQPa"
        "z5POpcfmbes8AiEApa3c04c4SG9RXOfFaLoREl/Ip6Bb6bzzBXVWBOr2Ju8wDQYJ"
        "KoZIhvcNAQELBQADggEBAIwXiYCWXr98J9pwFHNV3uyA//poq0gzC4ziMCES9A6c"
        "6WTnjVcngN+bRkGUrsgxfjMozIHJXtEWjYuUiBfFVmQ/krwHL/X1wsHLcmdbgHQZ"
        "PD1/4dfsG0vppSqloxnfwvPpqPe0f2jHBRmMlTg/H9hMWFHUndxM40K0592QedPC"
        "S9NUoAojEl1wCjMdCm4VXrhnOYa6VLplxbwCtDUkMqXhdeOEv2RY7+c/bEWJi2qT"
        "HEm+Zzfze7SuCFCSM9Ne3QTOlJIfgm2JTqs/H9ATCnRAIAokKQYHJa8uCdBilgb8"
        "PcIuelpLigrizaJxiWCDHcGYVgrG9nagZhoy1SwdRfg="
        "-----END CERTIFICATE-----\n";

    //Private functions to handle creating a service JWT. This JWT will be exchanged for a usable token. 
    String base64_encode(const unsigned char *bytes_to_encode,
                     unsigned int in_len);
    String base64_encode(String str);

 public:
 //Constructors for object
  gcptoken();                                                                         //DONE
  gcptoken(const char *service_kid, const char *target_audience, 
        const char *service_account, const char *service_private_key_str);   //DONE

  gcptoken &setServiceKid(const char *service_kid);                                   //DONE
  gcptoken &setTargetAudience(const char *target_audience);                           //DONE
  gcptoken &setServiceAccount(const char *service_account);                           //DONE
  gcptoken &setPrivateKey(const char *service_private_key_str);                       //DONE


  long long int getServiceJwtExpSecs();                                               //DONE
  long long int getScopedJwtExpSecs();                                                //DONE

//NOT SURE IF THESE TWO PROVIDE VALUE
  void setServiceJwtExpSecs(long long int exp_in_secs);                               //DONE - I DON'T THIS THIS ADDS VALUE
  void setScopedJwtExpSecs(long long int exp_in_secs);                                //DONE - I DON'T THIS THIS ADDS VALUE

  void setServiceTokenExpSecs(long long int exp_in_secs);                             //DONE
  void setScopedTokenExpSecs(long long int exp_in_secs);                              //DONE

//Create JWTs. JWT will be exchanged for 
  String createJWT(String payload, long long int time);                               //DONE

  String createServiceJWT(long long int time);                                        //DONE
  String createServiceJWT(long long int time, int jwtlife);                           //DONE
  String createScopedJWT(String scope, long long int time);                           //DONE
  String createScopedJWT(String scope, long long int time, int jwtlife);              //DONE

  String requestToken(String JWT, const char * tokenid);                                                    //DONE
  String requestServiceToken();                                                       //DONE
  String requestScopedToken();                                                        //DONE


//THESE NEED TO BE UPDATED WITH AUTO-REFRESH
  String getServiceToken();                                                           //DONE - DOES NOT AUTO UPDATE
  String getServiceToken(long long int time);                                         //DONE
  String getScopedToken();                                                            //DONE - DOES NOT AUTO UPDATE
  String getScopedToken(String scope, long long int time);                            //DONE

  void setServiceToken(String token);                                                 //DONE                                                         
  void setScopedToken(String token);                                                  //DONE

};