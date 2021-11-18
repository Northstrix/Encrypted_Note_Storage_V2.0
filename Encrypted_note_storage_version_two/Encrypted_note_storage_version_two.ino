/*
Encrypted Note Storage V2.0
Distributed under the MIT License
© Copyright Maxim Bortnikov 2021
For more information please visit
https://github.com/Northstrix/Encrypted_Note_Storage_V2.0
Required library:
https://github.com/fcgdam/DES_Library
*/
#include "serpent.h"
#include <sys/random.h>
#include "mbedtls/md.h"
#include "SPIFFS.h"
char *keys[]=
{"e43bb9373773441cd510b8aaa1878e179cf12e84cecef5c33cc30bf777b8feae1ff5d21feddfd3161fc988947472c5309bae3a6b9f80273720b8d811daaf2893" 
};
String tag;
String dec_stuff;
char *verk = "fba72814e175c7b459b456e17256fa5f42d06bcc29438bb9faa4fb5eef56603e143798b18db56cebb342411cfc7125c0b0e32c8d68994db1c3a809a9c67e578fc97d11e48f6a114b6db87816cd10caecd398653094d44fdd36efc6e01fe20a55043685bbad9acc2dbbb95e86b625bd25f619e4b893ccd350efe33cadea55f9a3d6b531bbb186896a63948818da2864ebffefec926627c1e7827a90a044cc5858457d7d813";

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
} 

void dump_hex (char *s, uint8_t bin[], int len)
{
  int i;
  String out = "";
  Serial.printf ("%s=", s);
  for (i=0; i<len; i++) {
    Serial.print(bin[i],HEX);
  }
  putchar('\n');
}

void split_by_eight(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  int d = res[0];
  int f = res[1];
  int g = res[2];
  int h = res[3];
  int r = res[4];
  int t = res[5];
  int y = res[6];
  int u = res[7];
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<sizeof(keys)/sizeof(char*); b++) {
    hex2bin (key, keys[b]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
  char rnd_nmbr[128];
  char key[128];
  //String h = "";
  int res = 0;
  for(int i = 0; i<128; i++){
    int c = esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;
    c += esp_random()%4;    
    int d = esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    d += esp_random()%4;
    int z = esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    z += esp_random()%4;
    int x = esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    x += esp_random()%4;
    //Serial.println(z);
    //Serial.println(x);
    //Serial.println(c);
    //Serial.println(d);
    if(c != 0 && d != 0)
    res = (16*c)+d;
    if(c != 0 && d == 0)
    res = 16*c;
    if(c == 0 && d != 0)
    res = d;
    if(c == 0 && d == 0)
    res = 0;
    rnd_nmbr[i] = char(res);
    //Serial.println(res);
    if(z != 0 && x != 0)
    res = (16*z)+x;
    if(z != 0 && x == 0)
    res = 16*z;
    if(z == 0 && x != 0)
    res = x;
    if(z == 0 && x == 0)
    res = 0;
    key[i] = char(res);
    //Serial.println(res);
    //h += getChar(c);
    //h += getChar(d);
  }
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  const size_t payloadLength = strlen(rnd_nmbr);
  const size_t keyLength = strlen(key);            
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) key, keyLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) rnd_nmbr, payloadLength);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  /*
  for(int i=0; i<32; i++){
  Serial.print(hmacResult[i] + " ");
  }
  */
  //Serial.print("Hash: ");
  int p = esp_random()%25;
  //Serial.println(y);
  ct2.b[0] = d;
  ct2.b[1] = f;
  ct2.b[2] = g;
  ct2.b[3] = h;
  ct2.b[4] = r;
  ct2.b[5] = t;
  ct2.b[6] = y;
  ct2.b[7] = u;
  int m = 8;
  for(int i = 0; i< 8; i++){
    ct2.b[m] = hmacResult[p+i];
    m++;
  }

  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
}

void split_dec(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<sizeof(keys)/sizeof(char*); i++) {
    hex2bin (key, keys[i]);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    for (int i=0; i<8; i++) {
      dec_stuff += char(ct2.b[i]);
    }
  }
}

void comp_tags(){
  byte hmacResult[32];
  int str_len = dec_stuff.length() + 1;
  char char_array[str_len];
  dec_stuff.toCharArray(char_array, str_len); 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  const size_t char_arrayLength = strlen(char_array);
  const size_t verkLength = strlen(verk);            
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *) verk, verkLength);
  mbedtls_md_hmac_update(&ctx, (const unsigned char *) char_array, char_arrayLength);
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);
  String ctag = "";
  for(int i=0; i<32; i++){
    if (hmacResult[i] < 16)
      ctag += 0;
    ctag += String(hmacResult[i], HEX);
  }
  Serial.println("Concatenated tag");
  Serial.println(tag);
  Serial.println("Computed tag");
  Serial.println(ctag);
  if(tag == ctag)
    Serial.println("Message authenticated successfully!");
  else
    Serial.println("Failed to authenticate the source of the message!");
}

void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
      Serial.println("An Error has occurred while mounting SPIFFS");
      return;
  }
}

void loop() {
    Serial.println();
    Serial.println("What do you want to do?");
    Serial.println("1.Encrypt record");
    Serial.println("2.Decrypt record");
    Serial.println("3.Extract record from built-in memory");
    Serial.println("4.Remove file");
    while (!Serial.available()) {}
    int x = Serial.parseInt();
    if(x == 1){
      Serial.println("Enter plaintext:");
      String str;
      while (!Serial.available()) {}
      str = Serial.readString();
      int str_len = str.length() + 1;
      char char_array[str_len];
      str.toCharArray(char_array, str_len);
      mbedtls_md_context_t ctx;
      mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
      const size_t char_arrayLength = strlen(char_array);
      const size_t verkLength = strlen(verk);
      byte hmacResult[32];
      mbedtls_md_init(&ctx);
      mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
      mbedtls_md_hmac_starts(&ctx, (const unsigned char *) verk, verkLength);
      mbedtls_md_hmac_update(&ctx, (const unsigned char *) char_array, char_arrayLength);
      mbedtls_md_hmac_finish(&ctx, hmacResult);
      mbedtls_md_free(&ctx);
      Serial.println("Ciphertext:");
      for(int i= 0; i< sizeof(hmacResult); i++){
        char str[3];
        sprintf(str, "%02x", (int)hmacResult[i]);
        Serial.print(str);
      }
      int p = 0;
      while( str_len > p+1){
        split_by_eight(char_array, p, str_len);
        p+=8;
      }
      Serial.println();
      Serial.println("Would you like to save the record into the built-in memory?");
      Serial.println("1.Yes");
      Serial.println("2.No");
      while (!Serial.available()) {}
      int y = Serial.parseInt();
      if(y == 1){
        Serial.println("Enter the filename:");
        String nm;
        while (!Serial.available()) {}
        nm = Serial.readString();
        Serial.println("Copy and paste the ciphertext:");
        String cipht;
        while (!Serial.available()) {}
        cipht = Serial.readString();
        File file = SPIFFS.open("/" + nm, FILE_WRITE);
        if (!file) {
          Serial.println("There was an error opening the file for writing");
          return;
        }
        if (file.print(cipht)) {
          Serial.println("File was written");
        } else {
          Serial.println("File write failed");
        }
        file.close();
      }
    }
    if(x == 2){
      String ct;
      Serial.println("Enter ciphertext");
      while (!Serial.available()) {}
      ct = Serial.readString();
      int ct_len = ct.length() + 1;
      char ct_array[ct_len];
      ct.toCharArray(ct_array, ct_len);
      int ext = 64;
      tag = "";
      dec_stuff = "";
      for(int i = 0; i<64; i++){
        tag += ct_array[i];
      }
      //Serial.println(tag);
      while( ct_len > ext){
      split_dec(ct_array, ct_len, 0+ext);
      ext+=32;
      }
      Serial.println("Plaintext");
      Serial.println(dec_stuff);
      comp_tags();
      dec_stuff = "";
    }
      if(x == 3){
        Serial.println("Enter the filename:");
        String nm;
        while (!Serial.available()) {}
        nm = Serial.readString();
        File file = SPIFFS.open("/" + nm);
        if(!file){
          Serial.println("Failed to open file for reading");
          return;
        }
        Serial.println("File Content:");
        while(file.available()){
          Serial.write(file.read());
        }
        file.close();
    }
      if(x == 4){
        Serial.println("Enter the filename:");
        String nm;
        while (!Serial.available()) {}
        nm = Serial.readString();
        SPIFFS.remove("/" + nm);
    }
}
