/*
 * aes.hh
 *
 *  Created on: June 2, 2018
 *      Author: Junjie Wang
 */

#ifndef AES_HH
#define AES_HH

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <stdint.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif


//#define AES128 1
//#define AES192 1
#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

#endif // #if defined(CTR) && (CTR == 1)



struct aes_flow_state {
	uint8_t key[AES_KEYLEN];
	uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	bool is_encryption;
};

class AES {
public:
	void *info_for_gpu;

	inline void init_automataState(struct aes_flow_state& state){
        for(int i = 0; i < AES_KEYLEN; i++){
            state.key[i] = i * 2;
        }
    }

    AES() {}
    ~AES() {}

    inline void nf_logic(void *pkt, struct aes_flow_state* state) {   
    	assert(pkt);

    	//uint16_t *msg = (uint16_t *)pkt;
        size_t len = *(size_t*)pkt;
        size_t len_padding = len;
        uint8_t *content = (uint8_t *)(pkt+sizeof(size_t));
        uint8_t *buffer = content;

        // padding to 16-byte alignment
        if(len % AES_BLOCKLEN != 0) {
        	len_padding = (len / AES_BLOCKLEN + 1) * AES_BLOCKLEN;
        	//buffer = (uint8_t *)malloc(len_padding);
        	//memset(buffer,0,len_padding);
       // 	memcpy(buffer, content, len);
        }
       // printf("lenpadding: %d\n",len_padding);

        // Initialize context
        struct AES_ctx ctx;
   		AES_init_ctx_iv(&ctx, state->key, state->iv);

        if(state->is_encryption){
           // printf("before encrypt\n");
           // printf("%.*s\n", len_padding, buffer);
           // printf("encrypt\n");
            AES_CBC_encrypt_buffer(&ctx, buffer, len_padding);
          //  printf("after encrypt\n");
           // printf("%.*s\n", len_padding, buffer);

        }else{
           // printf("before decrypt\n");
           // printf("%.*s\n", len_padding, buffer);
           // printf("decrypt\n");
            AES_CBC_decrypt_buffer(&ctx, buffer, len_padding);
           // printf("after decrypt\n");
          //  printf("%.*s\n", len_padding, buffer);
        }

    	// copy back
       // if(len % AES_BLOCKLEN != 0) {
       // 	memcpy(content, buffer, len);
       // }

    }


};

#endif /* AES_HH */

