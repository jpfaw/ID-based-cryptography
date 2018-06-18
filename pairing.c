// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <tepla/ec.h>
#include <openssl/sha.h>

typedef struct{
    EC_POINT P; // 楕円曲線上の点P
    EC_POINT Q; // 公開鍵
} Public_key;

void char_to_hash(unsigned char *hash, const char* id);
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size);
void exclusive_disjunction(unsigned char *ciphertext, const unsigned char *hash,
                           const char *text, const size_t hashSize, const size_t textSize);

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
    char m[]  = "hello_world!日本国民は、正当に選挙された国会における代表者を通じて行動し、われらとわれらの子孫のために、諸国民との協和による成果と、わが国全土にわたつて自由のもたらす恵沢を確保し、政府の行為によつて再び戦争の惨禍が起ることのないやうにすることを決意し、ここに主権が国民に存することを宣言し、この憲法を確定する。そもそも国政は、国民の厳粛な信託によるものであつて、その権威は国民に由来し、その権力は国民の代表者がこれを行使し、その福利は国民がこれを享受する。これは人類普遍の原理であり、この憲法は、かかる原理に基くものである。われらは、これに反する一切の憲法、法令及び詔勅を排除する。";

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

    /* --- g = e(P_A, sP)^r の計算 --- */
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

    /* --- gのハッシュ化 --- */
    unsigned char g_hash[SHA256_DIGEST_LENGTH];
    char_to_hash(g_hash, element_str);

    /* --- g_hashとmをXOR --- */
    unsigned char ciphertext[strlen(m)+1];
    exclusive_disjunction(ciphertext, g_hash, m, strlen(g_hash), strlen(m));

// 正常にXORできてるか検証
    unsigned char ciphertext2[strlen(m)+1];
    exclusive_disjunction(ciphertext2, g_hash, ciphertext, strlen(g_hash), strlen(m));
    printf("%s\n", ciphertext2);

// この段階で、Enc(m)→暗号文C=(U, v)=(rP, ciphertext)

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

/* -----------------------------------------
 * 文字列をSHA256でハッシュ化する関数
 * $0 ハッシュ化したものを入れるchar配列ポインタ
 * $1 ハッシュ化する文字列
  -----------------------------------------*/
void char_to_hash(unsigned char *hash, const char* id){
    
    //    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(id,strlen(id),hash);
    /* --- debug print --- */
    print_unsigned_char(hash, "hash", SHA256_DIGEST_LENGTH);
}

/* -----------------------------------------
 * 排他的論理和を計算する関数
 * $0 計算結果を入れるu_char配列ポインタ
 * $1 XORする値
 * $2 平文/暗号化文
 * $3 ハッシュの文字数
 * $4 テキストの文字数
 -----------------------------------------*/
void exclusive_disjunction(unsigned char *ciphertext, const unsigned char *hash,
                           const char *text, const size_t hashSize, const size_t textSize) {
    printf("hashSize: %d\ntextSize: %d\n", strlen(text), textSize);
    
    //TODO: hashの文字数がXORした後に変動する
    // 1文字ずつ分解し、XOR演算する
    for(size_t i=0; i<textSize; i++){
        ciphertext[i] = text[i]^hash[i%hashSize];
    }

    ciphertext[textSize] = '\0';
    print_unsigned_char(ciphertext, "ciphertext", textSize);
}

/* -----------------------------------------------
 * unsigned char(SHA256でハッシュ化した値)を出力する関数
 * $0 出力するu_char
 * $1 データ名（出力の最初にprintされる）
 * $2 データサイズ
 * 今は平文の方が短い場合のみ対応
 -----------------------------------------------*/
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size){
    printf("%s: ", dataName);
    for (size_t i=0; i<size; i++){
        printf("%02x", uc[i] );
    }
    printf("\n");
}
