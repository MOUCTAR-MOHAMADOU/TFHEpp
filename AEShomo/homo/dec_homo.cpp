#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

using namespace std;

using iksP = TFHEpp::lvl10param;
using bkP = TFHEpp::lvl02param;
using privksP = TFHEpp::lvl21param;

using TLWE_0 = TFHEpp::TLWE<typename bkP::domainP>;
using TLWE_1 = TFHEpp::TLWE<typename privksP::targetP>; // level 1

using TRLWE_1 = TFHEpp::TRLWE<typename privksP::targetP>; // level 1

// extern void sm4_setkey(unsigned long RoundKey[], unsigned char key[]);
//extern long AESKeyExpansion(unsigned char roundKeySchedule[],
//                            unsigned char key[], int keyBits);

const double clocks2seconds = 1. / CLOCKS_PER_SEC;

const uint32_t byte_mul2[8] = {0, 0, 0, 0, 0, 0, 0, 0};


//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    
int getSBoxValue(int num)
{
  int sbox[256] = {
      //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  //0
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  //1
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  //2
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  //3
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  //4
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  //5
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  //6
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  //7
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  //8
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  //9
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  //A
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  //B
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  //C
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  //D
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  //E
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; //F
  return sbox[num];
}

// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(28)
// Note that i starts at 1, not 0).
int Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

long AESKeyExpansion(unsigned char RoundKey[240],
                     unsigned char Key[], int NN)
{
  // Nk is the number of 32-bit works in the AES key (4,6, or 8)
  // Nr is the corresponding number of rounds (10, 12, 14)
  int Nr, Nk = NN / 32;
  switch (NN)
  {
  case 128:
    Nr = 10;
    break;
  case 192:
    Nr = 12;
    break;
  case 256:
    Nr = 14;
    break;
  default:
    printf("Aucune");
    // throw helib::InvalidArgument("Invalid key size: " + std::to_string(NN));
  }
  int i, j;
  unsigned char temp[4], k;
  // The first round key is the key itself.
  for (i = 0; i < Nk; i++)
  {
    RoundKey[i * 4] = Key[i * 4];
    RoundKey[i * 4 + 1] = Key[i * 4 + 1];
    RoundKey[i * 4 + 2] = Key[i * 4 + 2];
    RoundKey[i * 4 + 3] = Key[i * 4 + 3];
  }
  // All other round keys are found from the previous round keys.
  while (i < (Nk * (Nr + 1)))
  {
    for (j = 0; j < 4; j++)
    {
      temp[j] = RoundKey[(i - 1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
      // Function RotWord()
      {
        k = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = k;
      }
      // SubWord() takes a four-byte input word and applies the S-box
      // to each of the four bytes to produce an output word.
      // Function Subword()
      {
        temp[0] = getSBoxValue(temp[0]);
        temp[1] = getSBoxValue(temp[1]);
        temp[2] = getSBoxValue(temp[2]);
        temp[3] = getSBoxValue(temp[3]);
      }
      temp[0] = temp[0] ^ Rcon[i / Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        temp[0] = getSBoxValue(temp[0]);
        temp[1] = getSBoxValue(temp[1]);
        temp[2] = getSBoxValue(temp[2]);
        temp[3] = getSBoxValue(temp[3]);
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
    i++;
  }
  printf("roundkey %x \n" ,RoundKey[17]);
  return Nr + 1;
}
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 


// extern unsigned char SboxTable[16][16];
static const unsigned char SboxTable[16][16] =
    {
        // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F

// extern unsigned iSboxTable[16][16];
static const unsigned char iSboxTable[16][16] =
    {
        // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x52 , 0x09 , 0x6a , 0xd5 , 0x30 , 0x36 , 0xa5 , 0x38 , 0xbf , 0x40 , 0xa3 , 0x9e , 0x81 , 0xf3 , 0xd7 , 0xfb ,
        0x7c , 0xe3 , 0x39 , 0x82 , 0x9b , 0x2f , 0xff , 0x87 , 0x34 , 0x8e , 0x43 , 0x44 , 0xc4 , 0xde , 0xe9 , 0xcb ,
        0x54 , 0x7b , 0x94 , 0x32 , 0xa6 , 0xc2 , 0x23 , 0x3d , 0xee , 0x4c , 0x95 , 0x0b , 0x42 , 0xfa , 0xc3 , 0x4e ,
        0x08 , 0x2e , 0xa1 , 0x66 , 0x28 , 0xd9 , 0x24 , 0xb2 , 0x76 , 0x5b , 0xa2 , 0x49 , 0x6d , 0x8b , 0xd1 , 0x25 ,
        0x72 , 0xf8 , 0xf6 , 0x64 , 0x86 , 0x68 , 0x98 , 0x16 , 0xd4 , 0xa4 , 0x5c , 0xcc , 0x5d , 0x65 , 0xb6 , 0x92 ,
        0x6c , 0x70 , 0x48 , 0x50 , 0xfd , 0xed , 0xb9 , 0xda , 0x5e , 0x15 , 0x46 , 0x57 , 0xa7 , 0x8d , 0x9d , 0x84 ,
        0x90 , 0xd8 , 0xab , 0x00 , 0x8c , 0xbc , 0xd3 , 0x0a , 0xf7 , 0xe4 , 0x58 , 0x05 , 0xb8 , 0xb3 , 0x45 , 0x06 ,
        0xd0 , 0x2c , 0x1e , 0x8f , 0xca , 0x3f , 0x0f , 0x02 , 0xc1 , 0xaf , 0xbd , 0x03 , 0x01 , 0x13 , 0x8a , 0x6b ,
        0x3a , 0x91 , 0x11 , 0x41 , 0x4f , 0x67 , 0xdc , 0xea , 0x97 , 0xf2 , 0xcf , 0xce , 0xf0 , 0xb4 , 0xe6 , 0x73 ,
        0x96 , 0xac , 0x74 , 0x22 , 0xe7 , 0xad , 0x35 , 0x85 , 0xe2 , 0xf9 , 0x37 , 0xe8 , 0x1c , 0x75 , 0xdf , 0x6e ,
        0x47 , 0xf1 , 0x1a , 0x71 , 0x1d , 0x29 , 0xc5 , 0x89 , 0x6f , 0xb7 , 0x62 , 0x0e , 0xaa , 0x18 , 0xbe , 0x1b ,
        0xfc , 0x56 , 0x3e , 0x4b , 0xc6 , 0xd2 , 0x79 , 0x20 , 0x9a , 0xdb , 0xc0 , 0xfe , 0x78 , 0xcd , 0x5a , 0xf4 ,
        0x1f , 0xdd , 0xa8 , 0x33 , 0x88 , 0x07 , 0xc7 , 0x31 , 0xb1 , 0x12 , 0x10 , 0x59 , 0x27 , 0x80 , 0xec , 0x5f ,
        0x60 , 0x51 , 0x7f , 0xa9 , 0x19 , 0xb5 , 0x4a , 0x0d , 0x2d , 0xe5 , 0x7a , 0x9f , 0x93 , 0xc9 , 0x9c , 0xef ,
        0xa0 , 0xe0 , 0x3b , 0x4d , 0xae , 0x2a , 0xf5 , 0xb0 , 0xc8 , 0xeb , 0xbb , 0x3c , 0x83 , 0x53 , 0x99 , 0x61 ,
        0x17 , 0x2b , 0x04 , 0x7e , 0xba , 0x77 , 0xd6 , 0x26 , 0xe1 , 0x69 , 0x14 , 0x63 , 0x55 , 0x21 , 0x0c , 0x7d
    };

  // Decryption: Multiply by 9 for InverseMixColumns
  static const unsigned char mul9[16][16] =
  {
    0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
    0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
    0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
    0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
    0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
    0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
    0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
    0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
    0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
    0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
    0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
    0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
    0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
    0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
    0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
    0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46
  };

  // Decryption: Multiply by 11 for InverseMixColumns
  static const unsigned char mul11[16][16] =
  {
    0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
    0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
    0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
    0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
    0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
    0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
    0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
    0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
    0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
    0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
    0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
    0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
    0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
    0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
    0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
    0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3
  };

  // Decryption: Multiply by 13 for InverseMixColumns
  static const unsigned char mul13[16][16] =
  {
    0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
    0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
    0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
    0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
    0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
    0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
    0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
    0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
    0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
    0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
    0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
    0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
    0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
    0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
    0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
    0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97
  };

  // Decryption: Multiply by 14 for InverseMixColumns
  static const unsigned char mul14[16][16] =
  {
    0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
    0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
    0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
    0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
    0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
    0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
    0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
    0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
    0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
    0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
    0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
    0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
    0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
    0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
    0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
    0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d
  };    


void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dec_hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        dec_hex += bin_str[i] * pow(2, i);
    }
}

template <class P>
void XOR_Two(P &result, P &a, P &b)
{
    for (int i = 0; i < 8; i++)
    {
        for (int num = 0; num < bkP::domainP::n + 1; num++)
        {
            result[i][num] = a[i][num] + b[i][num];
        }
        // cout<<endl;
    }
}

template <class P>
void XOR_Four(P &result, P &a, P &b, P &c, P &d)
{
    XOR_Two<P>(result, a, b);
    XOR_Two<P>(result, result, c);
    XOR_Two<P>(result, result, d);
}

void MakeiSBoxTable(std::vector<TRLWE_1> &Table, const TFHEpp::Key<privksP::targetP> &key)
{
    // Tableau binaire pour l'inverse de la S-Box
    int iSbox_binary[256][8];
    // Remplissage de la table inverse S-Box
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(iSboxTable[i][j], bin_str); // Conversion de l'hexadécimal en binaire
            for (int k = 0; k < 8; k++)
            {
                iSbox_binary[i * 16 + j][k] = bin_str[k];
            }
        }
    }
    // mixpacking et chiffrement
    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)iSbox_binary[k * 128 + i][j];
            }
        }
        // Chiffrement de la table inverse S-Box et stockage dans la table
        Table[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}
void MixedPacking(TRLWE_1 &result, std::vector<TRLWE_1> &Table, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    // last bit
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result, select[7], Table[1], Table[0]);

    //BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];

    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }

    TFHEpp::BlindRotate_LUT<privksP>(result, bara, select, 7); //, resultOfCMUX);
}

void CipherAddRoundKey(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &rk, int round)
{
    for (int i = 0; i < 16; i++)
    {
        XOR_Two(cipher[i], cipher[i], rk[round * 16 + i]);
    }
}

void CipheriShiftRows(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &B) {
      for (int i = 0; i < 8; i++)
     {
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[0][i], B[0][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[1][i], B[13][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[2][i], B[10][i]);         
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[3][i], B[7][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[4][i], B[4][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[5][i], B[1][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[6][i], B[14][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[7][i], B[11][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[8][i], B[8][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[9][i], B[5][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[10][i], B[2][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[11][i], B[15][i]);

         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[12][i], B[12][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[13][i], B[9][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[14][i], B[6][i]);
         TFHEpp::HomCOPY<typename bkP::domainP>(cipher[15][i], B[3][i]);
     }
}
void MakeMul9Table(std::vector<TRLWE_1> &Table9, const TFHEpp::Key<privksP::targetP> &key)
{
    // Tableau binaire pour l'inverse de la S-Box
    int mul9_binary[256][8];
    // Remplissage de la table inverse S-Box
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(mul9[i][j], bin_str); // Conversion de l'hexadécimal en binaire
            for (int k = 0; k < 8; k++)
            {
                mul9_binary[i * 16 + j][k] = bin_str[k];
            }
        }
    }
    // mixpacking et chiffrement
    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)mul9_binary[k * 128 + i][j];
            }
        }
        // Chiffrement de la table inverse S-Box et stockage dans la table
        Table9[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}
void CipherMul9MixedPacking(TRLWE_1 &result9, std::vector<TRLWE_1> &Table9, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    // last bit
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result9, select[7], Table9[1], Table9[0]);
    //BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];
    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }
    TFHEpp::BlindRotate_LUT<privksP>(result9, bara, select, 7); //, resultOfCMUX);
}   
void MakeMul11Table(std::vector<TRLWE_1> &Table11, const TFHEpp::Key<privksP::targetP> &key)
{
    // Tableau binaire pour l'inverse de la S-Box
    int mul11_binary[256][8];
    // Remplissage de la table inverse S-Box
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(mul11[i][j], bin_str); // Conversion de l'hexadécimal en binaire
            for (int k = 0; k < 8; k++)
            {
                mul11_binary[i * 16 + j][k] = bin_str[k];
            }
        }
    }
    // mixpacking et chiffrement
    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)mul11_binary[k * 128 + i][j];
            }
        }
        // Chiffrement de la table inverse S-Box et stockage dans la table
        Table11[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}   
void CipherMul11MixedPacking(TRLWE_1 &result11, std::vector<TRLWE_1> &Table11, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    // last bit
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result11, select[7], Table11[1], Table11[0]);
    //BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];
    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }
    TFHEpp::BlindRotate_LUT<privksP>(result11, bara, select, 7); //, resultOfCMUX);
}
void MakeMul13Table(std::vector<TRLWE_1> &Table13, const TFHEpp::Key<privksP::targetP> &key)
{
    // Tableau binaire pour l'inverse de la S-Box
    int mul13_binary[256][8];
    // Remplissage de la table inverse S-Box
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(mul13[i][j], bin_str); // Conversion de l'hexadécimal en binaire
            for (int k = 0; k < 8; k++)
            {
                mul13_binary[i * 16 + j][k] = bin_str[k];
            }
        }
    }
    // mixpacking et chiffrement
    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)mul13_binary[k * 128 + i][j];
            }
        }
        // Chiffrement de la table inverse S-Box et stockage dans la table
        Table13[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}
void CipherMul13MixedPacking(TRLWE_1 &result13, std::vector<TRLWE_1> &Table13, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    // last bit
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result13, select[7], Table13[1], Table13[0]);
    //BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];
    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }
    TFHEpp::BlindRotate_LUT<privksP>(result13, bara, select, 7); //, resultOfCMUX);
}
void MakeMul14Table(std::vector<TRLWE_1> &Table14, const TFHEpp::Key<privksP::targetP> &key)
{
    int mul14_binary[256][8];
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(mul14[i][j], bin_str); 
            for (int k = 0; k < 8; k++)
            {
                mul14_binary[i * 16 + j][k] = bin_str[k];
            }
        }
    }
    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)mul14_binary[k * 128 + i][j];
            }
        }
        Table14[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}
void CipherMul14MixedPacking(TRLWE_1 &result14, std::vector<TRLWE_1> &Table14, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    TFHEpp::CMUXFFT<typename privksP::targetP>(result14, select[7], Table14[1], Table14[0]);
    privksP::targetP::T *bara = new privksP::targetP::T[8];
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }
    TFHEpp::BlindRotate_LUT<privksP>(result14, bara, select, 7); //, resultOfCMUX);
}

int main()
{
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);
    typedef TFHEpp::lvl1param P;
    // Generate key
    TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
    TFHEpp::EvalKey ek;
    ek.emplaceiksk<iksP>(*sk);
    ek.emplacebkfft<bkP>(*sk);
    ek.emplaceprivksk4cb<privksP>(*sk);

    ek.emplacebkfft<TFHEpp::lvl01param>(*sk); // used for identitybootstrapping


    std::cout << " ==================  MakeSBoxTable=================" << endl;
    std::vector<TRLWE_1> Table(2);
    MakeiSBoxTable(Table, sk->key.get<privksP::targetP>()); //Utiliser la clé TRLWE de niveau 1

    std::vector<TRLWE_1> Table9(2); 
    MakeMul9Table(Table9, sk->key.get<privksP::targetP>());    
    std::vector<TRLWE_1> Table11(2); 
    MakeMul11Table(Table11, sk->key.get<privksP::targetP>());    
    std::vector<TRLWE_1> Table13(2); 
    MakeMul13Table(Table13, sk->key.get<privksP::targetP>());
    std::vector<TRLWE_1> Table14(2); // Create Table14
    MakeMul14Table(Table14, sk->key.get<privksP::targetP>());


//k = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c  
//m = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
//M = 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
/*
    unsigned char plain[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                               0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

    unsigned char aeskey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
*/
  //           *********************************************************
  // Uncomment Part 2 if you need to read Key and PlainText from the keyboard.
  //     Part 2: ********************************************************

  //Clear the input buffer
  //flushall();
  int Nr=0, Nk=0, NN=128;
  Nk = NN / 32;  //4
  Nr = Nk + 6;   //10
  unsigned char plain[16], aeskey[16];  
  //Recieve the Key from the user
  printf("Enter the Key in hexadecimal: ");
  for(int i=0; i<16; i++)
  {
  scanf("%0hhx",&aeskey[i]);
  }
  printf("Enter the PlainText in hexadecimal: ");
  for(int i=0; i<16; i++)
  {
  scanf("%0hhx",&plain[i]);
  }
  //
  //             ******************************************************** 

    std::vector<TLWE_0> consByte(8);
    for (int i = 0; i < 8; i++)
    {
        // encrypt 0
        consByte[i] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)byte_mul2[i], bkP::domainP::alpha,
                                                                       sk->key.get<typename bkP::domainP>());
    }


    cout << " .........RoundKey........" << endl;
    // Compute the key expansion
    unsigned char RoundKey[240];
    long nRoundKeys = AESKeyExpansion(RoundKey, aeskey, 128);
    cout << " rounds: " << nRoundKeys << endl;


    std::vector<std::vector<TLWE_0>> rk;
    rk.resize(240);
    for (int i = 0; i < 240; i++)
    {
        int bin_str[8];
        rk[i].resize(8);
        HexToBinStr(RoundKey[i], bin_str);

        for (int j = 0; j < 8; j++)
        {
            // cout << bin_str[k] << " ";
            // encrypt TLWE in level 0
            rk[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[j], bkP::domainP::alpha,
                                                                        sk->key.get<typename bkP::domainP>());
            // cout << endl;
        }
    }

    std::vector<std::vector<TLWE_0>> cipher;
    cipher.resize(16);
    for (int i = 0; i < 16; i++)
    {
        cipher[i].resize(8);
    }
    // #pragma omp parallel for
    for (int i = 0; i < 16; i++)
    {
        int bin_str[8];
        HexToBinStr(plain[i], bin_str);
        // #pragma omp parallel for num_threads(8)
        for (int j = 0; j < 8; j++)
        {
            //  cout << bin_str[j]<<" ";
            cipher[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[j], bkP::domainP::alpha,
                                                                            sk->key.get<typename bkP::domainP>());
        }
        // cout <<endl;
    }




    std::chrono::system_clock::time_point start, end;
    double cb_totaltime = 0, lut_totaltime = 0, Idks_totaltime = 0, lutMul_totaltime;

    start = std::chrono::system_clock::now();

    CipherAddRoundKey(cipher, rk, 10);

//#if 1================================================================================
        cout << "=============round " << 10 << " CipherAddRoundKey============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================   

    std::vector<std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>>> bootedTGSW;

    bootedTGSW.resize(16);
    for (int i = 0; i < 16; i++)
    {
        bootedTGSW[i].resize(8);
    }

/////////////////////////////////////There will begin 9 rounds////////////////////////////////
   for (int i = 1; i < 10; i++)
//  for (int r = 9; r < 0; r--)
{
        int r = 10-i;
        std::vector<std::vector<TLWE_0>> B;
        B.resize(16);
        for (int i = 0; i < 16; i++)
        {
            B[i].resize(8);
        }
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                B[i][j] = cipher[i][j];
            }
        }    

        CipheriShiftRows(cipher, B);
        

//#if 1================================================================================
        cout << "=============round " << r << " CipheriShiftRows============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================

      
        std::chrono::system_clock::time_point cb_start, cb_end;
        cb_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        cipher[i][j], ek);
        }

        cb_end = std::chrono::system_clock::now();
        double cb_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
                .count();
        std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
        cb_totaltime += cb_elapsed;

        std::vector<TRLWE_1> lut_result(16); //
        std::chrono::system_clock::time_point lut_start, lut_end;
        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            MixedPacking(lut_result[i], Table, bootedTGSW[i]);
        }

        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
                .count();
        std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
        lut_totaltime += lut_elapsed;



        std::vector<std::vector<TLWE_1>> iSbox_value;
        iSbox_value.resize(16);

        for (int i = 0; i < iSbox_value.size(); i++)
        {
            iSbox_value[i].resize(8);
        }

        // SampleExtract level 1
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {

                TFHEpp::SampleExtractIndex<typename privksP::targetP>(iSbox_value[i][j], lut_result[i], j);
            }
        }



        std::chrono::system_clock::time_point ks_start, ks_end;

        ks_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                // level 1 -> level 0
                TFHEpp::IdentityKeySwitch<iksP>(B[i][j], iSbox_value[i][j], ek.getiksk<iksP>());
            }
        }
//#if 1================================================================================
        cout << "=============round " << r << " CipheriSubBytes============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(B[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================
        ks_end = std::chrono::system_clock::now();
        double ks_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
                .count();
        std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
        Idks_totaltime += ks_elapsed;
        
        
            
        CipherAddRoundKey(B, rk, r);        
        
//#if 1================================================================================
        cout << "=============round " << r << " CipherAddRoundKey============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(B[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif============================================================================== 

        std::chrono::system_clock::time_point lutMul_start, lutMul_end;
        lutMul_start = std::chrono::system_clock::now();               

        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        B[i][j], ek);
        }
              
        std::vector<TRLWE_1> lut_result9(16); //
        std::vector<TRLWE_1> lut_result11(16); //
        std::vector<TRLWE_1> lut_result13(16); //
        std::vector<TRLWE_1> lut_result14(16); //
        //std::vector<TRLWE_1> lut_res(16); //     
        for (int i = 0; i < 16; i++)
        {
            CipherMul9MixedPacking(lut_result9[i], Table9, bootedTGSW[i]);
            CipherMul11MixedPacking(lut_result11[i], Table11, bootedTGSW[i]);
            CipherMul13MixedPacking(lut_result13[i], Table13, bootedTGSW[i]);
            CipherMul14MixedPacking(lut_result14[i], Table14, bootedTGSW[i]);
        }

        std::vector<std::vector<TLWE_1>> mul9_value;
        std::vector<std::vector<TLWE_1>> mul11_value;
        std::vector<std::vector<TLWE_1>> mul13_value;
        std::vector<std::vector<TLWE_1>> mul14_value;        
        std::vector<std::vector<TLWE_0>> mul9;
        std::vector<std::vector<TLWE_0>> mul11;
        std::vector<std::vector<TLWE_0>> mul13;
        std::vector<std::vector<TLWE_0>> mul14;
        //std::vector<std::vector<TLWE_0>> mul_B;
        mul9_value.resize(16);
        mul11_value.resize(16);
        mul13_value.resize(16);
        mul14_value.resize(16);
        mul9.resize(16);
        mul11.resize(16);
        mul13.resize(16);
        mul14.resize(16);
        //mul_B.resize(16);
        for (int i = 0; i < 16; i++)
        {
            mul9_value[i].resize(8);
            mul11_value[i].resize(8);
            mul13_value[i].resize(8);
            mul14_value[i].resize(8);
            mul9[i].resize(8);
            mul11[i].resize(8);
            mul13[i].resize(8);
            mul14[i].resize(8);
            //mul_B[i].resize(8);
        }
     
        for (int i = 0; i < 16; i++) {          // Boucle externe de 0 à 4
            for (int j = 0; j < 8; j++) {      // Boucle interne de 0 à 4
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul9_value[i][j], lut_result9[i], j);
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul11_value[i][j], lut_result11[i], j);
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul13_value[i][j], lut_result13[i], j);
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(mul14_value[i][j], lut_result14[i], j);
            }          
        }
        for (int i = 0; i < 16; i++) {          // Boucle externe de 0 à 4
            for (int j = 0; j < 8; j++) {      // Boucle interne de 0 à 4
                TFHEpp::IdentityKeySwitch<iksP>(mul9[i][j], mul9_value[i][j], ek.getiksk<iksP>());           
                TFHEpp::IdentityKeySwitch<iksP>(mul11[i][j], mul11_value[i][j], ek.getiksk<iksP>());
                TFHEpp::IdentityKeySwitch<iksP>(mul13[i][j], mul13_value[i][j], ek.getiksk<iksP>());
                TFHEpp::IdentityKeySwitch<iksP>(mul14[i][j], mul14_value[i][j], ek.getiksk<iksP>());         
            }          
        }

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    CipheriMixColumns(cipher, mul9, mul11, mul13, mul14);

    std::vector<std::vector<TLWE_0>> tmp;
    tmp.resize(16);
    for (int i = 0; i < 16; i++)
    {
        tmp[i].resize(8);
    }
        XOR_Four(tmp[0], mul14[0], mul11[1], mul13[2], mul9[3]);
        XOR_Four(tmp[1], mul9[0], mul14[1], mul11[2], mul13[3]);        
        XOR_Four(tmp[2], mul13[0], mul9[1], mul14[2], mul11[3]);
        XOR_Four(tmp[3], mul11[0], mul13[1], mul9[2], mul14[3]); 
               
        XOR_Four(tmp[4], mul14[4], mul11[5], mul13[6], mul9[7]);
        XOR_Four(tmp[5], mul9[4], mul14[5], mul11[6], mul13[7]);         
        XOR_Four(tmp[6], mul13[4], mul9[5], mul14[6], mul11[7]);
        XOR_Four(tmp[7], mul11[4], mul13[5], mul9[6], mul14[7]);  
           
        XOR_Four(tmp[8], mul14[8], mul11[9], mul13[10], mul9[11]);
        XOR_Four(tmp[9], mul9[8], mul14[9], mul11[10], mul13[11]);         
        XOR_Four(tmp[10], mul13[8], mul9[9], mul14[10], mul11[11]);
        XOR_Four(tmp[11], mul11[8], mul13[9], mul9[10], mul14[11]); 
                
        XOR_Four(tmp[12], mul14[12], mul11[13], mul13[14], mul9[15]);
        XOR_Four(tmp[13], mul9[12], mul14[13], mul11[14], mul13[15]);         
        XOR_Four(tmp[14], mul13[12], mul9[13], mul14[14], mul11[15]);
        XOR_Four(tmp[15], mul11[12], mul13[13], mul9[14], mul14[15]);   
       //}

	  for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(cipher[i][j], tmp[i][j]);
        }
	  }

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    CipheriMixColumns(cipher, mul9, mul11, mul13, mul14);


        lutMul_end = std::chrono::system_clock::now();
        double lutMul_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lutMul_end - lutMul_start)
                .count();
        std::cout << " Mul9, Mul11, Mul13, Mul14 table one round costs: " << lutMul_elapsed << "us" << std::endl;
        lutMul_totaltime += lutMul_elapsed;

//#if 1================================================================================
        cout << "=============round " << r << " CipheriMixColumns============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================

}
/////////////////////////////////////There will end 9 rounds////////////////////////////////
        std::vector<std::vector<TLWE_0>> B;
        B.resize(16);
        for (int i = 0; i < 16; i++)
        {
            B[i].resize(8);
        }
        
        CipheriShiftRows(B, cipher);

//#if 1================================================================================
        cout << "=============round 1 CipheriShiftRows============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(B[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================

        std::chrono::system_clock::time_point cb_start, cb_end;
        cb_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        B[i][j], ek);
        }

        cb_end = std::chrono::system_clock::now();
        double cb_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
                .count();
        std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
        cb_totaltime += cb_elapsed;

        std::vector<TRLWE_1> lut_result(16); //
        std::chrono::system_clock::time_point lut_start, lut_end;
        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            MixedPacking(lut_result[i], Table, bootedTGSW[i]);
        }

        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
                .count();
        std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
        lut_totaltime += lut_elapsed;


        std::vector<std::vector<TLWE_1>> iSbox_value;
        iSbox_value.resize(16);

        for (int i = 0; i < iSbox_value.size(); i++)
        {
            iSbox_value[i].resize(8);
        }

        // SampleExtract level 1
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {

                TFHEpp::SampleExtractIndex<typename privksP::targetP>(iSbox_value[i][j], lut_result[i], j);
            }
        }

        // Key Switch to LWE B  on level 0
        std::vector<std::vector<TLWE_0>> C;
        C.resize(16);
        for (int i = 0; i < 16; i++)
        {
            C[i].resize(8);
        }

        std::chrono::system_clock::time_point ks_start, ks_end;

        ks_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                // level 1 -> level 0
                TFHEpp::IdentityKeySwitch<iksP>(C[i][j], iSbox_value[i][j], ek.getiksk<iksP>());
            }
        }
//#if 1================================================================================
        cout << "=============round 1  CipheriSubBytes============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(C[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
//#endif==============================================================================
        ks_end = std::chrono::system_clock::now();
        double ks_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
                .count();
        std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
        Idks_totaltime += ks_elapsed;



        CipherAddRoundKey(C, rk, 0);

        end = std::chrono::system_clock::now();
        double elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
                .count();


#if 1
    cout << "=============test last round ============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_hex = 0;
        int dec_bin[8];
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(C[i][j], sk->key.get<typename bkP::domainP>());
        }
        BinStrToHex(dec_hex, dec_bin);
        cout << hex << dec_hex << " ";
    }
    cout << endl;

#endif

    std::cout << "Circuitbootstrapping costs: " << cb_totaltime << "ms,  account for " << (cb_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "Lookup table costs: " << lut_totaltime << "us , account for " << (lut_totaltime / 1000 / elapsed) * 100 << "%" << std::endl;
    std::cout << "Idks costs: " << Idks_totaltime << "ms ,  account for " << (Idks_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "homoAES using Circuitbootstrapping costs: " << elapsed << "ms" << std::endl;

    return 0;
}


