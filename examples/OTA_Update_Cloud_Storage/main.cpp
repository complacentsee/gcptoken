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
#include "gcptoken.h"
#include <WiFiClientSecure.h>
#include "Update.h"

// Configuration for wifi, enter your credentials here
const char *ssid = "SSID HERE";
const char *password = "NETWORK PASSWORD";

// Configuration for NTP
const char* ntp_primary = "pool.ntp.org";
const char* ntp_secondary = "time.nist.gov";

//create gcp global object, setup const variables for class.
gcptoken serviceacc = gcptoken();
const char *service_kid = "56d14186258ba5d1b2c12475d6661c6d20d58350";
const char *service_aud = "32555940559.apps.googleusercontent.com";
const char *service_account = "github-public@gcptoken.iam.gserviceaccount.com";
const char * scope = "https://www.googleapis.com/auth/cloud-platform.read-only";
const char *service_private_key_str = 
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3+f2lytr27UW2\n"
  "LUK5QMTtDoxMz+e0h5eFi5cdEKG889RV+NdXjfkSOXmSosj1/lILr0GH1RBoS9o8\n"
  "6EdSm4TX0qdXmN05NhIJCq7nMWyPcNmQFPKED/17FTtPuZZ/1Qv0y4QSGJ0IDQO8\n"
  "G58YkS0ivubGzIRZKNxi2SKilEa3Mq3G0GV0QDFIbRLU6GZV4R6+RSfjAsLyeDcw\n"
  "uR4ErIyrbuUrrk1u3YGZUB2/aPEFVV3B+V+H2Ji42SnrF4qmnQ04Mz0nduHcThi6\n"
  "AET1vf4aIl6It8+XWrNTmyflnOdrCEsJy2isUd2dXxSCMFKZX9PFaO+MHzJZ2OhP\n"
  "Wi0u61+7AgMBAAECggEAAZ/bdX33tlEcryHHLQuSsY/R/VD4osdvtxDRzMKQ1bJG\n"
  "ywY0yzkdseOAB04YqCi5YLuzaxeehXfl/WkE+DMXVoXYTxWyc7GJMeXo6scCRmH2\n"
  "CdJQMd+nmqadV3Q0DVI8QMprPXL/hUqtdcO+ATbcRypDBLkEPM/3jN04nmbgw6Ko\n"
  "Y0avwCEgc9XqqJwNCZPqPHplMpw67/tia48KL0YRgcmHPfmkYvZAhT8ZC+WUvnJR\n"
  "UwV9Oc9tInEmFJecwfdSl3HQtCRJ2E5s7xshvTIBkWA8Mmt7dQzEtp5bCxDs1/6G\n"
  "JSU8s9G7m/d0WPsQp+bZl+9k5SDcUIwaF1cW9frZwQKBgQD3Y0G5T26FqmPaHIgL\n"
  "jLTjnu3iSxnp42YjZgURLw+bCFXd6q4oLNMJBgVu4OKIWB2HrPFdZsIzS5RKWr3G\n"
  "9xEOkOcloXzq+o26J5RZQl074gHihcpSFSucm0CdUr2ml3hnAGwsqELNIhf6ctPK\n"
  "zBWf1DWMls8PX8mNsL3JIab/HQKBgQC+YZt9eoz9Lq8MivAkY0uTbYNcJzRBXtq/\n"
  "UbnEcAt+FowvlYyq46zpdfeti18xzqpe7XIS9I8x30gubMzHtNHxCs3LvsEMcY7c\n"
  "tvbBFf9jhl7nXxaKQAUEtKLy8KyQpBAfwkWkiz1TkFZMmHgerHno+jOb8ZZIGuhv\n"
  "gvRxJT1qtwKBgE67BvqrvdfKP1b1x5ItaJAcT0a6cffOh/3yBODQIl5Li9BBVMWy\n"
  "ZkMz6Fy+MzoDGPrJ3lLEVj+u6PW05TrB/GqvUPDX8QJzVNGOsRarGTLqnYDy5U20\n"
  "MRn5CtpGr9ap1AarysF3lzLji9AH5UFgK+2ewqAIisMwz9tJCU1OaXA9AoGBAKCZ\n"
  "jGaknAz0dbyZ9AxuKxH5/ycc90rx7owYMCKS9k7uTGHTwW9jUrk6x64BdVN56GTd\n"
  "3y44WheTKLvpEjKhybySBZsLlqSdowtz2OJ3YRKfBq4dm9ESQml+zDsuZhQ6IlP4\n"
  "OXGd+CTnDLXepO4TR2AOuLyjZsf60vtGuFg+NvovAoGAb71b1eN/YfmT/sI7M+18\n"
  "VtDzogGsXWnD7dz4eRA0bViU1/pbROge2DCN0NeCQMZ7MOZY2PUr/+cddeSrArrh\n"
  "EEc0HNcr1hgc1INssnkww9BA9c65QhHSAp3E4vZWz4qxQBe/ClEKz34Zu+IW4WW1\n"
  "pS+kJ7Q8Qkt2D9YdOcvc0UI=\n"
  "-----END PRIVATE KEY-----\n";

//strings to handle the http client and certificates
String host = "storage.googleapis.com";
int port = 443;
String bin = "/gcptoken-test-firmware/firmware.bin"; // bin file name with a slash in front
const char *root_gcp_cert =
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

// Forward declarations for misc helper functions
void setupWifi();
void execOTA();
String getHeaderValue(String header, String headerName);

// Misc Files 
long contentLength = 0;
bool isValidContentType = false;



void setup() {
  void setupWifi();
  serviceacc = gcptoken(service_kid,service_aud,service_account,service_private_key_str);
  String token = serviceacc.getServiceToken(time(nullptr));
}

void loop() {
  delay(1000);
}

// BearerToken is a google cloud signed bearer token scoped for gcp cloud storage
// This OTA updated code  was lifted from another project based on AWS and 
// reused here for use with GCP. I was unable to locate the original 
// version of this code to credit.
void execOTA() {
  Serial.println("Connecting to: " + String(host));
  WiFiClientSecure client;
  if (client.connect(host.c_str(), port)) {
    // Connection Succeeded.
    // Fecthing the bin
    client.setCertificate(root_gcp_cert);
    Serial.println("Fetching Bin: " + String(bin));

    // Get the contents of the bin file
    client.print(String("GET ") + bin + " HTTP/1.1\r\n" +
                 "Host: " + host + "\r\n" +
                 "Cache-Control: no-cache\r\n" +
                 "Authorization: Bearer " + serviceacc.getScopedToken(scope,time(nullptr)) + "\r\n" +
                 "Connection: close\r\n\r\n");

    unsigned long timeout = millis();
    while (client.available() == 0) {
      if (millis() - timeout > 5000) {
        Serial.println("Client Timeout !");
        client.stop();
        return;
      }
    }

    while (client.available()) {
      // read line till /n
      String line = client.readStringUntil('\n');
      // remove space, to check if the line is end of headers
      line.trim();

      // if the the line is empty,
      // this is end of headers
      // break the while and feed the
      // remaining `client` to the
      // Update.writeStream();
      if (!line.length()) {
        //headers ended
        break; // and get the OTA started
      }

      // Check if the HTTP Response is 200
      // else break and Exit Update
      if (line.startsWith("HTTP/1.1")) {
        if (line.indexOf("200") < 0) {
          Serial.println("Got a non 200 status code from server. Exiting OTA Update.");
          break;
        }
      }

      // extract headers here
      // Start with content length
      if (line.startsWith("Content-Length: ")) {
        contentLength = atol((getHeaderValue(line, "Content-Length: ")).c_str());
        Serial.println("Got " + String(contentLength) + " bytes from server");
      }

      // Next, the content type
      if (line.startsWith("Content-Type: ")) {
        String contentType = getHeaderValue(line, "Content-Type: ");
        Serial.println("Got " + contentType + " payload.");
        if (contentType == "application/octet-stream") {
          isValidContentType = true;
        }
      }
    }
  } else {
    // Connect to S3 failed
    // May be try?
    // Probably a choppy network?
    Serial.println("Connection to " + String(host) + " failed. Please check your setup");
    // retry??
    // execOTA();
  }

  // Check what is the contentLength and if content type is `application/octet-stream`
  Serial.println("contentLength : " + String(contentLength) + ", isValidContentType : " + String(isValidContentType));

  // check contentLength and content type
  if (contentLength && isValidContentType) {
    // Check if there is enough to OTA Update
    bool canBegin = Update.begin(contentLength);

    // If yes, begin
    if (canBegin) {
      Serial.println("Begin OTA. This may take 2 - 5 mins to complete. Things might be quite for a while.. Patience!");
      // No activity would appear on the Serial monitor
      // So be patient. This may take 2 - 5mins to complete
      size_t written = Update.writeStream(client);

      if (written == contentLength) {
        Serial.println("Written : " + String(written) + " successfully");
      } else {
        Serial.println("Written only : " + String(written) + "/" + String(contentLength) + ". Retry?" );
        // retry??
        // execOTA();
      }

      if (Update.end()) {
        Serial.println("OTA done!");
        if (Update.isFinished()) {
          Serial.println("Update successfully completed. Rebooting.");
          ESP.restart();
        } else {
          Serial.println("Update not finished? Something went wrong!");
        }
      } else {
        Serial.println("Error Occurred. Error #: " + String(Update.getError()));
      }
    } else {
      // not enough space to begin OTA
      // Understand the partitions and
      // space availability
      Serial.println("Not enough space to begin OTA");
      client.flush();
    }
  } else {
    Serial.println("There was no content in the response");
    client.flush();
  }
}

//helper function to setup wifi
void setupWifi() {
  Serial.println("Starting wifi");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.println("Connecting to WiFi");
  int wifi_connection_timer = millis();
  while (WiFi.status() != WL_CONNECTED){
    delay(100);
    Serial.println(".");
  } 
  configTime(0, 0, ntp_primary, ntp_secondary);
  Serial.println("Waiting on time sync...");
  while (time(nullptr) < 1510644967){
    delay(10);
  }
  delay(10);
}

String getHeaderValue(String header, String headerName) {
  return header.substring(strlen(headerName.c_str()));
}