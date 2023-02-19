/******************************************************************************
 * File Name: DES.cpp
 *
 * Description: implementation of DES encryption/decryption
 *
 * Authors: Mahmoud Yasser Mohamed
            Mahmoud Mohamed Mohsen
            Osama Muhammad Ramadan
            Aya mohamed elhusseny
            Aya mohamed abdelhalim
 *******************************************************************************/


#include <iostream>
#include <fstream>
#include <iostream>
#include <string>

typedef unsigned long long int u64;

using namespace std;
u64 generatedKeys[16];


int initialPermutation[64] = {58 , 50 , 42 , 34 , 26 , 18 , 10 , 2 , 60 , 52  , 44 , 36 , 28 , 20 , 12 , 4 , 62 , 54 , 46 , 38 , 30 , 22 , 14 ,
                               6 , 64 , 56 , 48 , 40 , 32 , 24 , 16 , 8 , 57 , 49 , 41 , 33 , 25 , 17 , 9 , 1 , 59 , 51 , 43 , 35 , 27 , 19 , 11 ,
                               3 , 61 , 53 , 45 , 37 , 29 , 21 , 13 , 5 , 63 , 55 , 47 , 39 , 31 , 23 , 15 , 7};
int inversePermutation[64] = {40 , 8 , 48 , 16 , 56 , 24 , 64 , 32 , 39 , 7 ,47 , 15 , 55 , 23 , 63 , 31 , 38 , 6 , 46 , 14 , 54 , 22 , 62 ,
                                       30 , 37 , 5 , 45 , 13 , 53 , 21 , 61 , 29 , 36 , 4 , 44 , 12 , 52 , 20 , 60 , 28 ,35 , 3 , 43 , 11 , 51 , 19 , 59 ,
                                       27 , 34 , 2 , 42 , 10 , 50 , 18 , 58 , 26 , 33 , 1 , 41 , 9 , 49 , 17 , 57 , 25};
int expansionPermutation[48] = {32 , 1 , 2 , 3 , 4 , 5 , 4 , 5 , 6 , 7 , 8 , 9 ,  8 , 9 , 10 , 11 , 12 , 13 , 12 , 13 , 14 , 15 , 16 , 17 , 16 , 17 ,
                                 18 , 19 , 20 , 21 , 20 , 21 , 22 , 23 , 24 , 25 , 24 , 25 , 26 , 27 , 28 , 29 , 28 , 29 , 30 , 31 , 32 , 1};
int Permutation[32] = {16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14,
                       32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};


int sbox_table[] = {14, 4, 13,  1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0 , 15 , 7 , 4 , 14 , 2 ,  13 , 1 , 10 ,6 , 12 , 11 , 9 , 5 , 3 , 8,
                    4 , 1, 14 , 8 , 13 , 6 , 2 , 11 , 15 , 12 , 9 , 7 , 3 , 10 , 5, 0,
                    15 , 12 , 8 , 2 , 4, 9, 1, 7, 5, 11 , 3, 14 ,10 , 0 , 6, 13,

                    15 , 1, 8 , 14 , 6 , 11 , 3 , 4 , 9 , 7 , 2 , 13 , 12 , 0 , 5 , 10  ,
                    3 , 13 , 4 , 7 , 15 , 2 , 8 , 14 , 12 , 0 , 1 , 10 , 6 , 9 , 11 , 5,
                    0 , 14 , 7 , 11 , 10 , 4 , 13 , 1 , 5 , 8 , 12 , 6 , 9 , 3 , 2 , 15,
                    13 , 8 , 10 , 1 , 3 , 15 , 4 , 2 , 11 , 6 , 7 , 12 , 0 , 5 , 14 , 9,

                    10 , 0 , 9, 14 , 6 , 3 , 15 , 5 , 1 , 13 , 12 , 7 , 11 , 4 , 2 , 8,
                    13 , 7 , 0 , 9 , 3 , 4 , 6 , 10 , 2 , 8 , 5 , 14 , 12 , 11 , 15 , 1,
                    13 , 6 , 4 , 9 , 8 , 15 , 3 , 0 , 11 , 1 , 2 , 12 , 5 , 10 , 14 , 7,
                    1 , 10 ,13 , 0 , 6 , 9, 8 , 7, 4 , 15 , 14 , 3 , 11 , 5 , 2 , 12,

                    7 , 13 , 14 , 3 , 0 , 6 , 9 , 10 , 1 , 2, 8 , 5 , 11 , 12 , 4 , 15,
                    13 , 8 , 11 , 5 , 6 , 15 , 0 , 3 , 4 , 7 , 2 , 12 , 1 , 10 , 14 , 9,
                    10 , 6 , 9 , 0 , 12 , 11 , 7 , 13 , 15 , 1 , 3 , 14 , 5 , 2 , 8 , 4,
                    3 , 15 , 0 , 6 , 10 , 1 , 13 , 8 , 9 , 4 , 5 , 11 , 12 , 7 , 2 , 14,

                    2 , 12 , 4 , 1 , 7 , 10 , 11 , 6 , 8 , 5 , 3 , 15 , 13 , 0 , 14 , 9,
                    14 , 11 , 2 , 12 , 4 , 7 , 13 , 1 , 5 , 0 , 15 , 10 , 3 , 9 , 8 , 6,
                    4 , 2 , 1 , 11 , 10 , 13 , 7 , 8 , 15 , 9 , 12 , 5 , 6 , 3 , 0 , 14,
                    11 , 8 , 12 , 7 , 1 , 14 , 2 , 13 , 6 , 15 , 0 , 9 , 10 , 4 , 5 , 3,

                    12 , 1 , 10 , 15 , 9 , 2 , 6 , 8 , 0 , 13 , 3 , 4 , 14 , 7 , 5 , 11,
                    10 , 15 , 4 , 2 , 7 , 12 , 9 , 5 , 6 , 1 , 13 , 14 , 0 , 11 , 3 , 8,
                    9 , 14 , 15 , 5 , 2 , 8 , 12 , 3 , 7 , 0 , 4 , 10 , 1 , 13 , 11 , 6 ,
                    4 , 3 , 2 , 12 , 9 , 5 , 15 , 10 , 11 , 14 , 1 , 7 , 6 , 0 , 8 , 13,

                    4 , 11 , 2 , 14 , 15 , 0 , 8 , 13 , 3 , 12 , 9 , 7 , 5 , 10 , 6 , 1,
                    13 , 0 , 11 , 7 , 4 , 9 , 1 , 10 , 14 , 3 , 5 , 12 , 2 , 15 , 8 , 6 ,
                    1 , 4 , 11 , 13 , 12 , 3 , 7 , 14 , 10 , 15 , 6 , 8 , 0 , 5 , 9 , 2,
                    6 , 11 , 13 , 8 , 1 , 4 , 10 , 7 , 9 , 5 , 0 , 15 , 14 , 2 , 3 , 12,

                    13 , 2 , 8 , 4 , 6 , 15 , 11 , 1 , 10 , 9 , 3 , 14 , 5 , 0 , 12 , 7,
                    1 , 15 , 13 , 8 , 10 , 3 , 7 , 4 , 12 , 5 , 6 , 11 , 0 , 14 , 9 , 2,
                    7 , 11 , 4 , 1 , 9 , 12 ,14 , 2 , 0 , 6 , 10 , 13 , 15 , 3 , 5 , 8,
                    2 , 1 , 14 , 7 , 4 , 10 , 8 , 13 , 15 , 12 , 9 , 0 , 3 , 5 , 6 , 11
};

int PC1[] = {57, 49, 41, 33, 25, 17, 9,
             1, 58, 50, 42, 34, 26, 18,
             10, 2, 59, 51, 43, 35, 27,
             19,    11,    3, 60, 52, 44, 36,
             63, 55, 47, 39, 31, 23, 15,
             7, 62, 54, 46, 38, 30, 22,
             14, 6, 61, 53, 45, 37, 29,
             21, 13, 5, 28, 20, 12, 4};

int PC2[] = {14, 17, 11, 24, 1, 5,
             3, 28, 15, 6, 21, 10,
             23, 19, 12, 4, 26, 8,
             16, 7, 27, 20, 13, 2,
             41, 52, 31, 37, 47, 55,
             30, 40, 51, 45, 33, 48,
             44, 49, 39, 56, 34, 53,
             46, 42, 50, 36, 29, 32};



void fileToString (string& str, string fileName)
{
    ifstream myfile (fileName, ios_base::in);


    if (myfile.is_open ())
    {
        while (myfile)
        {
            string temp;
            myfile >> temp;
            str += temp;
        }
    }

    myfile.close ();
}



string ToHexa (u64 x, bool is2)
{
    char hex[] = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    string temp = "", output = "";
    while (x)
    {
        temp += hex[x & 0b1111];
        x >>= 4;
    }

    int size = 16;
    if (is2) size = 2;

    while (temp.size () < size)
    {
        temp += "0";
    }

    for (int i = temp.size () - 1; i >= 0; i--)
        output += temp[i];

    return output;
}


string ToASCII (u64 x, bool is2)
{
    string s = ToHexa (x, is2);
    string output = "";

    int i = 0;
    for (; i + 2 <= s.size () - 1; i += 2)
        output += (char)stoi (s.substr (i, 2), nullptr, 16);
    output += (char)stoi (s.substr (i), nullptr, 16);
    return output;
}


u64 ToInteger (string x)
{ 
    int i = 0, indx = 0;
    string temp = "";
    u64 result;
    for (; i < x.size (); i++)
    { 
        temp += ToHexa ((int)x[i], true); 

    }

    result = stoull (temp, NULL, 16);

    return result;

}


u64 HexaToDecimal (string hexa)
{
    int length = hexa.size ();

    u64 base = 1,
    decimal_value = 0;
    for (int i = length - 1; i >= 0; i--)
    {

        if (hexa[i] >= '0' && hexa[i] <= '9')
        {
            decimal_value += (int (hexa[i]) - 48) * base;
            base = base * 16;
        }

        else if (hexa[i] >= 'A' && hexa[i] <= 'Z')
        {
            decimal_value += (int (hexa[i]) - 55) * base;
            base = base * 16;
        }

    }
    return decimal_value;
}

u64 permute (u64 decimalInput, int permutation_table[], int outputsize, int inputsize)
{
    u64 output = 0;
    for (int i = 0; i < outputsize; i++)
    {
        int idx = permutation_table[i];
        u64 data = 0;

        if (((1ULL << (inputsize - idx)) & decimalInput) != 0)
        {
            data = 1;
        } else { data = 0; }
        output = (output | (data << outputsize - i - 1));

    }
    return output;
}

u64 sbox (u64 x)
{
    u64 output = 0;
    for (int i = 0; i < 8; i++)
    {
        u64 sbox_input = x & (0b111111ULL << 42 - i * 6);
        sbox_input >>= 42 - i * 6;
        int row_indx = ((sbox_input >> 5) << 1) + (sbox_input & 0b1);
        int column_indx = (sbox_input & 0b011110) >> 1;
        output += ((u64)sbox_table[row_indx * 16 + i * 64 + column_indx] << ((7 - i) * 4));
    }
    return output;
}

u64 Round (u64 data, u64 roundkey)
{
    u64 leftdata, rightdata;
    leftdata = (data >> 32);
    rightdata = (data & 4294967295);
    u64 expansionPerm = permute (rightdata, expansionPermutation, 48, 32);
    u64 Xoring = (expansionPerm ^ roundkey);


    u64 sboxOutput = sbox (Xoring);

    u64 permutation = permute (sboxOutput, Permutation, 32, 32);
    u64 nextright = permutation ^ leftdata;
    u64 nextleft = rightdata;

    return (nextleft << 32) | nextright;

}

void generateKeys (u64 generatedKeys[], string key_file)
{

    string keyfile = "";
    fileToString (keyfile, key_file);


    u64 key = HexaToDecimal (keyfile);

    key = permute (key, PC1, 56, 64);
    int shift[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    int i = 0;
    for (int round = 1; round <= 16; round++)
    {
        u64 leftKey = key >> 28;

        u64 rightKey = key & 268435455;

        leftKey = ((leftKey << (shift[round - 1])) | (leftKey >> (28 - (shift[round - 1])))) & 268435455;
        rightKey = ((rightKey << (shift[round - 1])) | (rightKey >> (28 - (shift[round - 1])))) & 268435455;

        leftKey = leftKey << 28;
        u64 shiftedKey = leftKey | rightKey;

        u64 c2 = permute (shiftedKey, PC2, 48, 56);
        generatedKeys[i++] = c2;
        key = (shiftedKey);
    }

}


u64 encrypt (u64 plainText)
{

    plainText = permute (plainText, initialPermutation, 64, 64);
    for (int round = 1; round <= 16; round++)
    {
        plainText = Round (plainText, generatedKeys[round - 1]);
    }
    u64 leftPlaitext, rightPlaintext;
    leftPlaitext = plainText >> 32;
    rightPlaintext = (plainText & 4294967295);
    rightPlaintext = rightPlaintext << 32;

    u64 output = rightPlaintext | leftPlaitext;
    u64 cipherText = permute (output, inversePermutation, 64, 64);
    return cipherText;
}



u64 decrypt (u64 cipherText)
{

    cipherText = permute (cipherText, initialPermutation, 64, 64);
    for (int round = 1; round <= 16; round++)
    {
        cipherText = Round (cipherText, generatedKeys[16 - round]);
    }

    u64 leftCiphertext, rightCiphertext;
    leftCiphertext = cipherText >> 32;
    rightCiphertext = (cipherText & 4294967295);
    rightCiphertext = rightCiphertext << 32;

    u64 output = rightCiphertext | leftCiphertext;
    u64 plainText = permute (output, inversePermutation, 64, 64);
    return plainText;
}

void encryption (string input_file, string output_file)

{
    const int length = 8;
    char* array = new char[length];

    ifstream n (input_file);
    n.seekg (0, ios::end);
    u64 size = n.tellg () / 8;
    u64* encryptedData = new u64[size];
    u64* data = new u64[size];
    u64 counter = 0, input = 0;
    ifstream myfile (input_file);
    if (myfile)
    {
        while (myfile.peek () != EOF)
        {
            myfile.read (array, 8);
            string str = "";
            for (int i = 0; i < 8; i++)
            {
                str += array[i];
            }
            u64 integerdata = ToInteger (str);
            data[counter++] = integerdata;

        }
    }
    myfile.close ();
    for (u64 i = 0; i < counter; i++)
    {
        encryptedData[i] = encrypt (data[i]);
    }


    ofstream outputFileAscii (output_file, ios_base::out);
    ofstream outputFileHex ("hex.txt", ios_base::out);
    for (u64 i = 0; i < counter; i++)
    {
        outputFileAscii << ToASCII (encryptedData[i], false);
        outputFileHex << ToHexa (encryptedData[i], false);
    }
    outputFileAscii.close ();
    outputFileHex.close ();
}

void decryption (string input_file, string output_file)
{
    const int length = 16;
    char* array = new char[length];

    ifstream n (input_file);
    n.seekg (0, ios::end);
    u64 size = n.tellg () / 16;
    u64* decryptedData = new u64[size];
    u64* data = new u64[size];
    u64 counter = 0, input = 0;
    ifstream myfile (input_file);
    if (myfile)
    {
        while (myfile.peek () != EOF)
        {
            myfile.read (array, 16);
            string str = "";
            for (int i = 0; i < 16; i++)
            {
                str += array[i];
            }
            u64 integerdata = stoull ((str), NULL, 16);
            data[counter++] = integerdata;


        }
    }
    myfile.close ();
    for (u64 i = 0; i < counter; i++)
    {
        decryptedData[i] = decrypt (data[i]);
    }

    ofstream outputFileAscii (output_file, ios_base::out);

    for (u64 i = 0; i < counter; i++)
    {
        outputFileAscii << ToASCII (decryptedData[i], false);

    }
    outputFileAscii.close ();

}



int main (int argc, char* argv[])
{
    generateKeys (generatedKeys, argv[3]);
    if ((string)argv[1] == "encrypt") encryption ((string)argv[2], (string)argv[4]);
    else decryption ("hex.txt", (string)argv[4]);
    return 0;
}
