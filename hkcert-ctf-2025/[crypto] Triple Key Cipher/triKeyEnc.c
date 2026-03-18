#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#define BLOCK_SIZE 16

FILE *fp;

void Hash(unsigned char *msg, unsigned len)
{
    unsigned char tmp[32];
    memset(tmp, 0, 32);
    memcpy(tmp, msg, len < 32 ? len : 32);
    unsigned char hash[32];
    SHA256(tmp, 32, hash);
    memcpy(msg, hash, len < 32 ? len : 32);
}

void urandom(unsigned char *buf, int len)
{
    fread(buf, 1, len, fp);
}

void twist(unsigned char *msg) {
    unsigned long long in1 = 0, in2 = 0;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        in1 <<= 4;
        in2 <<= 4;
        in1 |= msg[i] & 0xf;
        in2 |= msg[i] >> 4;
    }
    unsigned long long out1 = 0, out2 = 0;
    out1 = ((3*in1*in1 + in2) ^ (4*in2*in2)) - 2*in1;
    out2 = ((2*in1+in1) ^ (3*in1*in1 + in2)) * (2*in2) - ((3*in1*in1 + in2)*(3*in1*in1 + in2)*(3*in1*in1 + in2) & (8*in2*in2*in2)) - in2;
    for(int i = 0; i < BLOCK_SIZE; i++)
    {
        msg[i] = out1 & 0xf;
        msg[i] |= out2 & 0xf;
        out1 >>= 4;
        out2 >>= 4;
    }
}

void triple_key_cipher(int len, unsigned char *msg, unsigned char *key1, unsigned char *key2, unsigned char* key3)
{
    if(len % BLOCK_SIZE != 0)
        return;
    int i, j, k;
    unsigned char key_expand[BLOCK_SIZE][BLOCK_SIZE];
    unsigned char tmp = 0;
    twist(key1);
    for(i = 0; i < BLOCK_SIZE; i++)
        key_expand[0][i] = key1[i];
    for(i = 0; i < BLOCK_SIZE-1; i++)
    {
        key_expand[i+1][0] = key_expand[i][BLOCK_SIZE-1] * key1[0];
        for(j = 0; j < BLOCK_SIZE-1; j++)
            key_expand[i+1][j+1] = key_expand[i][j] + key_expand[i][BLOCK_SIZE-1] * key1[j+1];
    }
    printf("leak: "); for(int i = 0; i < BLOCK_SIZE; i++) printf("%.2hhx", key_expand[BLOCK_SIZE-1][i]); printf("\n");
    for(int block = 0; block < len / BLOCK_SIZE; block++)
    {
        twist(key3);
        unsigned char enc[BLOCK_SIZE];
        for(i = 0; i < BLOCK_SIZE; i++)
            enc[i] = msg[i+block*BLOCK_SIZE] * key2[0];
        for(i = 1; i < BLOCK_SIZE; i++)
        {
            for(j = 0; j < BLOCK_SIZE-i; j++)
                enc[i+j] = enc[i+j] + key2[i] * msg[j+block*BLOCK_SIZE];
            for(j = BLOCK_SIZE-i; j < BLOCK_SIZE; j++)
                for(k = 0; k < BLOCK_SIZE; k++)
                    enc[k] = enc[k] + key2[i] * msg[j+block*BLOCK_SIZE] * key_expand[i+j-BLOCK_SIZE][k];
        }
        for(i = 0; i < BLOCK_SIZE; i++)
            msg[i+block*BLOCK_SIZE] = enc[i] ^ key3[i];
    }
}

int main()
{
    setvbuf(stdin,NULL, 2, 0);
    setvbuf(stdout,NULL, 2, 0);

    fp = fopen("/dev/urandom", "r");

    int i, j;
    unsigned char key1[BLOCK_SIZE], key2[BLOCK_SIZE], key3[BLOCK_SIZE];
    urandom(key2, BLOCK_SIZE);
    Hash(key2, BLOCK_SIZE);
    for(j = 0; j < 10; j++)
    {
        write(1, "1. Encrypt\n2. Get flag\n3. Quit\nYour choice: ", 44);
        unsigned int opcode;
        read(0, &opcode, 1);
        getchar();
        printf("%hhx\n", opcode);
        switch (opcode)
        {
        case '1':
            write(1, "Message: ", 9);
            unsigned char msg[2*BLOCK_SIZE];
            memset(msg, 0, 2*BLOCK_SIZE);
            read(0, msg, 2*BLOCK_SIZE);
            Hash(msg, 2*BLOCK_SIZE);
            urandom(key1, BLOCK_SIZE); urandom(key3, BLOCK_SIZE);
            triple_key_cipher(2*BLOCK_SIZE, msg, key1, key2, key3);
            printf("enc: "); for(int i = 0; i < 2*BLOCK_SIZE; i++) printf("%.2hhx", msg[i]); printf("\n");
            break;
        case '2':
            write(1, "Key: ", 5);
            unsigned char usr_key[BLOCK_SIZE];
            read(0, usr_key, BLOCK_SIZE);
            if(memcmp(usr_key, key2, BLOCK_SIZE) == 0)
            {
                FILE* file = fopen("flag", "r");
                unsigned char flag[60];
                fread(flag, 1, 60, file);
                fclose(file);
                printf("flag: %s\n", flag);
                return 0;
            }
            else
            {
                write(1, "Wrong!\n", 7);
            }
            break;
        case '3':
            return 0;
        default:
            break;
        }
    }
    fclose(fp);
    return 0;
}
