#include <bits/stdc++.h>

#define blockSize 4
// Macro to find the product of x ({02}) and the argument to xtime modulo {03}
#define xtime(x) (((x << 1) & (15)) ^ (((x >> 3) & 1) * 0x3))
// Macro to multiply numbers in the Galois Field
#define Multiply(x, y) (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^ ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))
int rounds = 0;
int keyLength = 0;
unsigned char plaintext[16], encrypted[16], state[4][4];
unsigned char roundKey[240], Key[32];

// Returns S-box value
int get_SBox_Value(int num)
{
    int sbox[16] = {0x6, 0xb, 0x5, 0x4, 0x2, 0xe, 0x7, 0xa, 0x9, 0xd, 0xf, 0xc, 0x3, 0x1, 0x0, 0x8};
    return sbox[num];
}
// Returns inverse  S-box value
int get_SBox_Inverse(int num)
{
    int rsbox[16] = {14, 13, 4, 12, 3, 2, 0, 6, 15, 8, 7, 1, 11, 9, 5, 10};
    return rsbox[num];
}

// Lookup Table for round constant word array
int Rcon[10] = {1, 2, 4, 8, 3, 6, 12, 11, 5, 10};

// Deduces round keys from the primary Key provided
void Expand_Keys()
{
    int i, j;
    unsigned char temp[4], k;
    // Use the primary Key for first round
    for (i = 0; i < keyLength; i++)
    {
        roundKey[i * 4] = Key[i * 4];
        roundKey[i * 4 + 1] = Key[i * 4 + 1];
        roundKey[i * 4 + 2] = Key[i * 4 + 2];
        roundKey[i * 4 + 3] = Key[i * 4 + 3];
    }
    // Each subsequent round key is deduced from previously deduced round keys
    while (i < (blockSize * (rounds + 1)))
    {
        for (j = 0; j < 4; j++)
        {
            temp[j] = roundKey[(i - 1) * 4 + j];
        }
        if (i % keyLength == 0)
        {
            // Rotate the bytes in a word to the left.
            {
                k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
            }
            // Take a four-byte input and apply the S-box to each of the four bytes
            {
                temp[0] = get_SBox_Value(temp[0]);
                temp[1] = get_SBox_Value(temp[1]);
                temp[2] = get_SBox_Value(temp[2]);
                temp[3] = get_SBox_Value(temp[3]);
            }

            temp[0] = temp[0] ^ Rcon[(i / keyLength) - 1];
        }
        else if (keyLength > 6 && i % keyLength == 4)
        {       temp[0] = get_SBox_Value(temp[0]);
                temp[1] = get_SBox_Value(temp[1]);
                temp[2] = get_SBox_Value(temp[2]);
                temp[3] = get_SBox_Value(temp[3]);
        }
        roundKey[i * 4 + 0] = roundKey[(i - keyLength) * 4 + 0] ^ temp[0];
        roundKey[i * 4 + 1] = roundKey[(i - keyLength) * 4 + 1] ^ temp[1];
        roundKey[i * 4 + 2] = roundKey[(i - keyLength) * 4 + 2] ^ temp[2];
        roundKey[i * 4 + 3] = roundKey[(i - keyLength) * 4 + 3] ^ temp[3];
        i++;
    }
}

// Add round key to state by XOR-ing
void Add_Round_Key(int round)
{
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] ^= roundKey[round * blockSize * 4 + i * blockSize + j];
}

// Substitute state matrix values with corresponding S-box values
void Sub_Bytes()
{
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = get_SBox_Value(state[i][j]);
}

// Same as Sub_Bytes, but uses reverse SBox
void Inv_Sub_Bytes()
{
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = get_SBox_Inverse(state[i][j]);
}

// Shift the rows in the state to the left by the row number value
void Shift_Rows()
{
    unsigned char temp;

    // First row by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Second row by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Third row by 3
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// Same as Shift_Rows, but shifts right instead
void Inv_Shift_Rows()
{
    unsigned char temp;

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// Mixes the columns of the state matrix
void Mix_Columns()
{
    int i;
    unsigned char x1, x2, x3;
    for (i = 0; i < 4; i++)
    {
        x1 = state[0][i];
        x3 = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        x2 = state[0][i] ^ state[1][i];
        x2 = xtime(x2);
        state[0][i] ^= x2 ^ x3;
        x2 = state[1][i] ^ state[2][i];
        x2 = xtime(x2);
        state[1][i] ^= x2 ^ x3;
        x2 = state[2][i] ^ state[3][i];
        x2 = xtime(x2);
        state[2][i] ^= x2 ^ x3;
        x2 = state[3][i] ^ x1;
        x2 = xtime(x2);
        state[3][i] ^= x2 ^ x3;
    }
    for (int i = 0; i < 4; i++)
    {
        state[i][0] &= 15;
        state[i][1] &= 15;
        state[i][2] &= 15;
        state[i][3] &= 15;
    }
}

// Inverse mixing of columns
void Inv_Mix_Columns()
{
    int i;
    unsigned char x1, x2, x3, x4;
    for (i = 0; i < 4; i++)
    {
        x1 = state[0][i];
        x2 = state[1][i];
        x3 = state[2][i];
        x4 = state[3][i];

        state[0][i] = Multiply(x1, 0x0e) ^ Multiply(x2, 0x0b) ^ Multiply(x3, 0x0d) ^ Multiply(x4, 0x09);
        state[1][i] = Multiply(x1, 0x09) ^ Multiply(x2, 0x0e) ^ Multiply(x3, 0x0b) ^ Multiply(x4, 0x0d);
        state[2][i] = Multiply(x1, 0x0d) ^ Multiply(x2, 0x09) ^ Multiply(x3, 0x0e) ^ Multiply(x4, 0x0b);
        state[3][i] = Multiply(x1, 0x0b) ^ Multiply(x2, 0x0d) ^ Multiply(x3, 0x09) ^ Multiply(x4, 0x0e);
    }
}

void Encrypt()
{
    int i, j, round = 0;

    // Copy plaintext to state array
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] = plaintext[i * 4 + j];
        }
    }
    // Add the first round key to the state before starting the rounds
    Add_Round_Key(0);
    // The first rounds-1 rounds are the same
    for (round = 1; round < rounds; round++)
    {
        Sub_Bytes();
        Shift_Rows();
        Mix_Columns();
        Add_Round_Key(round);
    }
    // Last round has no Mix_Columns()
    Sub_Bytes();
    Shift_Rows();
    Add_Round_Key(rounds);
    // Copy the state array to output
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            encrypted[i * 4 + j] = state[j][i];
}

void Decrypt()
{
    int i, j, round = 0;
    // Copy cyphertext to state array
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[j][i] = encrypted[i * 4 + j];

    Add_Round_Key(rounds);

    for (round = rounds - 1; round > 0; round--)
    {
        Inv_Shift_Rows();
        Inv_Sub_Bytes();
        // round=rounds-1;
        Add_Round_Key(round);
        Inv_Mix_Columns();
    }

    Inv_Shift_Rows();
    Inv_Sub_Bytes();
    Add_Round_Key(0);

    // Copy the state array to output
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            plaintext[i * 4 + j] = state[j][i];
}
void helper(int userOp){
    int i=0;
    // Ask user for the key in HEX
    printf("Provide Key in HEX: \nKey should be 16 hexadecimal Long:\nFormat should be like i.e, one  space between each char in hex : 0 1 2 3 4 5 6 7 8 9 a b c d e f\n After Entering 16 character long key seperated by space press enter\nEnter Key:\n");
    for(i = 0; i < 16; i++)
		scanf("%x", &Key[i]);
    // Expand_Keys before encryption/decryption
    Expand_Keys();

    if(userOp==1){
        // Ask user for the plaintext to be encrypted in HEX
        printf("Provide Plaintext in HEX: \n Plaintext should be 16 hexadecimal Long:\nFormat should be like i.e, one  space between each char in hex : 9 8 3 a b c d e f 1 2 3 4 3 5 7\n After Entering 16 character long plaintext seperated by space press enter\nEnter Plaintext:\n");
        for (i = 0; i < blockSize * 4; i++)
            scanf("%x", &plaintext[i]);
        Encrypt();

        // Output the encrypted text
        printf("\nEncrypted / ciphertext: \n");
        for (i = 0; i < keyLength * blockSize; i++)
            printf("%x ", encrypted[i]);
        printf("\n\n");
    }
    else if(userOp==2){
        printf("Provide Ciphertext in HEX: \n Ciphertext should be 16 hexadecimal Long:\nFormat should be like i.e, one  space between each char in hex : 9 8 3 a b c d e f 1 2 3 4 3 5 7\n After Entering 16 character long ciphertext seperated by space press enter\nEnter Ciphertext:\n");
        for (i = 0; i < blockSize * 4; i++)
            scanf("%x", &encrypted[i]);
        Decrypt();
        {   //The State in final round is:
            printf("Final round State Matrix is:\n");
            printf("%x %x %x %x\n", state[0][0], state[0][1], state[0][2], state[0][3]);
            printf("%x %x %x %x\n", state[1][0], state[1][1], state[1][2], state[1][3]);
            printf("%x %x %x %x\n", state[2][0], state[2][1], state[2][2], state[2][3]);
            printf("%x %x %x %x\n", state[3][0], state[3][1], state[3][2], state[3][3]);
        }
        printf("\nDecrypted text: \n");
        for (i = 3; i < blockSize * 4; i++)
            printf("%x ", plaintext[i]);
        printf("\n\n");
    }
    else{
        printf("Not a valid option: Try 1 or 2\n");
    }
    printf("Done\n");
}
int main()
{
    int i;rounds = 64;keyLength = 4;rounds = 10;    
    
    int userOp=1;
    printf("Instructions:\n 0. To exit Press 0:\n 1. To encrypt Press 1:\n 2. To decrypt Press 2: \n  Enter Option Number:\n");
    scanf("%d",&userOp);
    while(userOp!=0){
        helper(userOp);
        printf("Instructions:\n 0. To exit Press 0:\n 1. To encrypt Press 1:\n 2. To decrypt Press 2: \n  Enter Option Number:\n");
        scanf("%d",&userOp);
    }
    return 0;
}