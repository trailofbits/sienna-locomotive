#ifndef Rc4x_H
#define Rc4x_H

#include <stdint.h>

class RC4x {
public:

    explicit RC4x( const uint8_t key[], size_t keyLen, bool insecure=false ): discarded(insecure) {
        size_t  i = 0;
        uint8_t j = 0;
        
        if( nullptr==key ) {
            key = nullkey;
            keyLen = sizeof(nullkey);
        }
        for( i=0; i<256; i++ ) {
            S[i] = (uint8_t)i;
        }

        for( i=0; i<256; i++ ) {
            j += S[i] + key[i%keyLen];
            RC4x::swap( &S[i], &S[j] );
        }

    }

    explicit RC4x(bool insecure) : RC4x( nullptr, 0, true ) {};

    void
    encrypt( uint8_t* plain, uint8_t* cipher, size_t len ) {

        if( !discarded ) {
            discarded = true;
            uint8_t null1[1536] = {0};
            uint8_t null2[1536] = {0};
            encrypt( null1, null2, 1536 );
        }
        size_t  i;
        uint8_t j;
        for( i=0; i<len; i++ ) {
            I1++;
            I2 += S[I1];
            swap( &S[I1], &S[I2] );
            j = S[I1] + S[I2];
            cipher[i] = plain[i] ^ S[j];
        }
        
    }

    static void swap( uint8_t* a, uint8_t* b ) {
        uint8_t     tmp;
        tmp     = *a;
        *a      = *b;
        *b      = tmp;
    };


    static bool tester() {
        const uint8_t   plain[8]    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const uint8_t   key[8]      = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
        const uint8_t   test[8]     = {0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79};
        uint8_t         cipher[8]   = {};

        RC4x rc4( key, sizeof(key), true  );
        rc4.encrypt( (uint8_t*)plain, (uint8_t*)cipher, sizeof(cipher));

        bool ret = memcmp( cipher, test, sizeof(cipher) )==0;
        return ret;
    }


private:
    bool        discarded = false;
    uint8_t     I1 = 0;
    uint8_t     I2 = 0;
    uint8_t     S[256];
    const uint8_t nullkey[32] = { 0x69, 0x06, 0x60, 0xd3, 0xb3, 0xa9, 0x2c, 0xa6, 0xa4, 0x6b, 0xe8, 0xea, 0x26, 0x5a, 0x61, 0xb6 };
};

#endif
