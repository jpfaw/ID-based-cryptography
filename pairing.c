// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <tepla/ec.h>
#include<openssl/sha.h>

typedef struct{
    EC_POINT P; // 楕円曲線上の点P
    EC_POINT Q; // 公開鍵
} Public_key;

void char_to_hash(unsigned char *hash, char* id);

// IDを貰ってE上の点Pへのハッシュ変換を行う(引数: 点P, ID)
void hash1(EC_POINT P,const char *id) {
    point_map_to_point(P, id, strlen(id), 128); // SHA-256
}

// E上の点から有限体へのハッシュ関数
void hash2(EC_PAIRING P) {
    //P->g3
}

// 鍵生成局が使用するマスター秘密鍵を生成する(引数: 秘密鍵を入れる変数, 上限値)
void create_master_private_key(mpz_t private_key, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(private_key, state, n); // privae_key = (0 <= random value <= n-1)
}

// 鍵生成局がユーザに配布する秘密鍵(K_x)を生成する(引数: 代入する点, 点P, ID, マスター秘密鍵)
void create_user_private_key(EC_POINT K_X, EC_POINT P_X, const char* id, mpz_t master_private_key) {
    hash1(P_X, id);                             // 1. ID -> E上の点P_X
    point_mul(K_X, master_private_key, P_X);    // 2. K_X = sP_X
}

// 公開鍵を生成する(引数: 公開鍵を入れる変数, 秘密鍵, 点P)
void create_public_key(Public_key public_key, const mpz_t private_key, const EC_POINT P) {
    point_set(public_key.P, P);
    point_mul(public_key.Q, private_key, P); // Q = private_key * P
}

// mpz_tでランダムな値を生成・返却する(引数: 上限値)
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(op, state, n);
}




int main(void) {
/* ----- セットアップ ----- */
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set_ui(limit, 2);
    mpz_pow_ui(limit, limit, 254);
    gmp_printf ("%s is %Zd\n", "limit", limit);

    /* --- マスター秘密鍵生成 --- */
    mpz_t s;
    mpz_init(s);
    create_master_private_key(s, limit);
    gmp_printf ("%s is %Zd\n", "secret", s);

    /* --- ペアリングの生成 --- */
    EC_PAIRING p;
    pairing_init(p, "ECBN254a");

    /* --- 楕円曲線 E の生成 --- */
    // 楕円曲線E = p->g1
    // 有限体F = p->g3

    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, p->g1);
    point_random(P);
    printf("P=   ");
    point_print(P);

    /* --- sP の計算 --- */
    EC_POINT sP;
    point_init(sP, p->g1);
    point_mul(sP, s, P);
    printf("sP=  ");
    point_print(sP);

/* ----- Encode ----- */
    /* --- IDと平文m --- */
    char id[] = "shirase";
    char m[]  = "hello_world!";

    /* --- AさんのIDをP_Aに変換 --- */
    EC_POINT P_A;
    point_init(P_A, p->g2);
    hash1(P_A, id);
    printf("P_A= ");
    point_print(P_A);

    /* --- ランダムな値 r --- */
    mpz_t r;
    mpz_init(r);
    create_mpz_t_random(r, limit);
    gmp_printf ("%s is %Zd\n", "random", r);

    /* --- rP の計算 --- */
    EC_POINT rP;
    point_init(rP, p->g1);
    point_mul(rP, r, P);
    printf("rP=  ");
    point_print(rP);

    /* --- e(P_A, sP)^r の計算 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, sP, P_A, p); // 第3引数はg2を参照のこと
    element_pow(g, g, r);       // r乗する
    element_print(g);

    /* --- gを文字列化 --- */
    int element_str_length = element_get_str_length(g);
    char *element_str;
    element_str = (char *)malloc(element_str_length+1);
    if(element_str == NULL) {
        printf("メモリが確保できませんでした。\n");
        return 0;
    }else{
        printf("element_str_length: %d\n", element_str_length);
        element_get_str(element_str, g);
        printf("element_str: %s\n", element_str);
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char_to_hash(hash, element_str);

    //TODO: gとmをxor


/* ----- Decode ----- */



/* ----- 領域の解放 ----- */
    free(element_str);
    mpz_clears(limit, s, r, NULL);
    element_clear(g);
    point_clear(P);
    point_clear(sP);
    point_clear(P_A);
    point_clear(rP);
    pairing_clear(p);

    printf("--- 正常終了 ---\n");
    return 0;
}

/* --- 文字列をSHA256でハッシュ化 --- */
void char_to_hash(unsigned char *hash, char* id){
    
    //    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(id,strlen(id),hash);
    
    /* --- debug print --- */
    printf("hash: ");
    for ( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ ){
        printf("%02x", hash[i] );
    }
    printf("\n");
}

void hash_to_ell_point(mpz_t x) {
    
}

void ell_point_to_field() {
    // TODO: mod p?
}


