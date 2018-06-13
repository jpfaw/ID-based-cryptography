// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <tepla/ec.h>
#include <openssl/md5.h>

unsigned long int ID_to_hash(char* id);

typedef struct{
    EC_POINT P; // 楕円曲線上の点P
    EC_POINT Q; // 公開鍵
} Public_key;

// 鍵生成局が使用するマスター秘密鍵を生成する(引数: 秘密鍵を入れる変数, 上限値)
void create_master_private_key(mpz_t private_key, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(private_key, state, n); // privae_key = (0 <= random number <= n-1)
}

// 鍵生成局がユーザに配布する秘密鍵を生成する(引数: 秘密鍵を入れる変数, ID, マスター秘密鍵)
void create_private_key(mpz_t private_key, const char* ID, mpz_t master_private_key) {
    //TODO: IDをハッシュ化して整数値に変換
}

// 公開鍵を生成する(引数: 公開鍵を入れる変数, 秘密鍵, 点P)
void create_public_key(Public_key public_key, const mpz_t private_key, const EC_POINT P) {
    point_set(public_key.P, P);
    point_mul(public_key.Q, private_key, P); // Q = private_key * P
}

int main(void) {
    
    /* --- 変数宣言 --- */
    EC_PAIRING p;                       // type of pairing
    EC_POINT P;                         // type of point
    Element g;                          // type of Finite field
    
    /* --- 初期化 --- */
    pairing_init(p, "ECBN254a");
    point_init(P, p->g2);
    point_random(P);                    // 楕円曲線上の点P
    element_init(g, p->g3);
    
    /* --- マスター秘密鍵生成 --- */
    mpz_t master_private_key;
    mpz_t limit;
    mpz_inits(limit,master_private_key, NULL);
    // 最大値の設定
    mpz_set_ui(limit,2);
    mpz_pow_ui(limit,limit,254);
    create_master_private_key(master_private_key, limit);
    
    
    
    //    point_print(a);
    //    element_print(g);
    
    char msg[] = "abcde";
    
    /* --- Encode --- */
    
    /* --- Decode --- */
    
   /* --- 領域の解放 --- */
    mpz_clear(limit);
    mpz_clear(master_private_key);
    point_clear(P);
    element_clear(g);
    pairing_clear(p);
    
    // Key Generation Center
    //    EC_GROUP G;
    //    curve_init(G, "ec_bn254_fpa");
    
    
    mpz_t rop;
    mpz_init(rop);
    unsigned long int op = ID_to_hash("hogehoge");
    mpz_set_ui (rop, op);
    gmp_printf ("%s is an mpz %Zd\n", "here", rop);
    return 0;
}

unsigned long int ID_to_hash(char* id) {
    MD5_CTX c;
    unsigned char md[MD5_DIGEST_LENGTH];
    char mdString[33];
    int r, i;
    
    r = MD5_Init(&c);
    if(r != 1) { perror("init"); exit(1); }
    r = MD5_Update(&c, id, strlen(id));
    if(r != 1) { perror("update"); exit(1); }
    r = MD5_Final(md, &c);
    if(r != 1) { perror("final"); exit(1); }
    
    for(i = 0; i < 16; i++)
        sprintf(&mdString[i * 2], "%02x", (unsigned int)md[i]);
    
    printf("md5 digest: %s\n", mdString);
    unsigned long int v = strtol(mdString, NULL, 16);
    return v;
}

void ell_point_to_field() {
    // TODO: mod p?
}


