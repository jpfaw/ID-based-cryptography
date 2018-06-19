// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <tepla/ec.h>
#include <openssl/sha.h>

// プロトタイプ宣言
void print_green_color(const char *text);
void hash1(EC_POINT P,const char *id);
void create_mpz_t_random(mpz_t op, const mpz_t n);
void char_to_hash(unsigned char *hash, const char* id);
void create_master_private_key(mpz_t private_key, const mpz_t n);
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size);
void exclusive_disjunction(unsigned char *ciphertext, const unsigned char *hash,
                           const char *text, const size_t hashSize, const size_t textSize);

int main(void) {
/* ----- セットアップ ----- */
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set_ui(limit, 2);
    mpz_pow_ui(limit, limit, 254);
    print_green_color("limit = ");
    gmp_printf ("%s%Zd\n", "", limit);

    /* --- マスター秘密鍵生成 --- */
    mpz_t s;
    mpz_init(s);
    create_master_private_key(s, limit);
    print_green_color("secret = ");
    gmp_printf ("%s%Zd\n", "", s);

    /* --- ペアリングの生成 --- */
    EC_PAIRING p;
    pairing_init(p, "ECBN254a");

    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, p->g2);
    point_random(P);
    print_green_color("P =  ");
    point_print(P);

    /* --- sP の計算 --- */
    EC_POINT sP;
    point_init(sP, p->g2);
    point_mul(sP, s, P);
    print_green_color("sP = ");
    point_print(sP);

/* ----- Encode ----- */
    /* --- IDと平文mとmの長さ --- */
    char id[] = "shirase";
//    char m[]  = "hello_world!";
    char m[]  = "hello_world!日本国民は、正当に選挙された国会における代表者を通じて行動し、われらとわれらの子孫のために、諸国民との協和による成果と、わが国全土にわたつて自由のもたらす恵沢を確保し、政府の行為によつて再び戦争の惨禍が起ることのないやうにすることを決意し、ここに主権が国民に存することを宣言し、この憲法を確定する。そもそも国政は、国民の厳粛な信託によるものであつて、その権威は国民に由来し、その権力は国民の代表者がこれを行使し、その福利は国民がこれを享受する。これは人類普遍の原理であり、この憲法は、かかる原理に基くものである。われらは、これに反する一切の憲法、法令及び詔勅を排除する。";
    int m_length = strlen(m);

    /* --- AさんのIDをP_Aに変換 --- */
    EC_POINT P_A;
    point_init(P_A, p->g1);
    hash1(P_A, id);
    print_green_color("P_A = ");
    point_print(P_A);

    /* --- ランダムな値 r --- */
    mpz_t r;
    mpz_init(r);
    create_mpz_t_random(r, limit);
    print_green_color("random = ");
    gmp_printf ("%s%Zd\n", "", r);

    /* --- rP の計算 --- */
    EC_POINT rP;
    point_init(rP, p->g2);
    point_mul(rP, r, P);
    print_green_color("rP = ");
    point_print(rP);

    /* --- g = e(P_A, sP)^r の計算 --- */
    Element g;
    element_init(g, p->g3);
    pairing_map(g, P_A, sP, p); // $1はg1, $2はg2を使用している必要がある
    element_pow(g, g, r);       // r乗する
    print_green_color("g =  ");
    element_print(g);

    /* --- gを文字列化 --- */
    int g_element_str_length = element_get_str_length(g);
    char *g_element_str;
    g_element_str = (char *)malloc(g_element_str_length+1);
    if(g_element_str == NULL) {
        printf("メモリが確保できませんでした。\n");
        return 0;
    }else{
        element_get_str(g_element_str, g);
        print_green_color("g_element_str_length = ");
        printf("%d\n", g_element_str_length);
        print_green_color("g_element_str = ");
        printf("%s\n", g_element_str);
    }

    /* --- gのハッシュ化 --- */
    unsigned char g_hash[SHA256_DIGEST_LENGTH];
    char_to_hash(g_hash, g_element_str);

    /* --- g_hashとmをXOR --- */
    unsigned char ciphertext[strlen(m)+1];
    exclusive_disjunction(ciphertext, g_hash, m, strlen(g_hash), m_length);

    // この段階で、Enc(m)→暗号文C=(U, v)=(rP, ciphertext)

// 正常にXORできてるか検証
//    unsigned char ciphertext2[strlen(m)+1];
//    exclusive_disjunction(ciphertext2, g_hash, ciphertext, strlen(g_hash), m_length);
//    printf("main ciphertext2: %s\n", ciphertext2);

/* ----- Decode ----- */
    /* --- Aさんの秘密鍵K_Aを生成 --- */
    EC_POINT K_A;
    point_init(K_A, p->g1);
    point_mul(K_A, s, P_A);
    print_green_color("K_A = ");
    point_print(K_A);

    /* --- e(K_A, U)の計算 --- */
    Element a;
    element_init(a, p->g3);
    pairing_map(a, K_A, rP, p);
    print_green_color("a = ");
    element_print(a);

    /* --- aを文字列化 --- */
    int a_element_str_length = element_get_str_length(a);
    char *a_element_str;
    a_element_str = (char *)malloc(a_element_str_length+1);
    if(a_element_str == NULL) {
        printf("メモリが確保できませんでした。\n");
        return 0;
    }else{
        element_get_str(a_element_str, a);
        print_green_color("a_element_str_length = ");
        printf("%d\n", a_element_str_length);
        print_green_color("a_element_str = ");
        printf("%s\n", a_element_str);
    }

    /* --- aのハッシュ化 --- */
    unsigned char a_hash[SHA256_DIGEST_LENGTH];
    char_to_hash(a_hash, a_element_str);

    /* --- v XOR a --- */
    unsigned char ciphertext3[m_length+1];
    exclusive_disjunction(ciphertext3, a_hash, ciphertext, strlen(a_hash), m_length);
    print_green_color("結果 : ");
    printf("%s\n", ciphertext3);

/* ----- 領域の解放 ----- */
    free(g_element_str);
    free(a_element_str);
    mpz_clears(limit, s, r, NULL);
    element_clear(g);
    element_clear(a);
    point_clear(P);
    point_clear(sP);
    point_clear(P_A);
    point_clear(rP);
    point_clear(K_A);
    pairing_clear(p);

    printf("--- 正常終了 ---\n");
    return 0;
}

/* -----------------------------------------------
 * IDを貰ってE上の点Pへのハッシュ変換を行う関数
 * $0 ハッシュ変換したものを入れるEC_POINT(点P)
 * $1 ID
 -----------------------------------------------*/
void hash1(EC_POINT P,const char *id) {
    point_map_to_point(P, id, strlen(id), 128); // SHA-256
}

/* -----------------------------------------------
 * 鍵生成局が使用するマスター秘密鍵を生成する関数
 * $0 秘密鍵を入れる変数
 * $1 上限値
 -----------------------------------------------*/
void create_master_private_key(mpz_t private_key, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(private_key, state, n); // privae_key = (0 <= random value <= n-1)
}

/* -----------------------------------------------
 * mpz_tでランダムな値を生成する関数
 * $0 生成した値を入れる変数
 * $1 上限値
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm(op, state, n);
}

/* -------------------------- ↓暗号と関係ない関数↓ -------------------------- */

/* -----------------------------------------------
 * 文字列をSHA256でハッシュ化する関数
 * $0 ハッシュ化したものを入れるchar配列ポインタ
 * $1 ハッシュ化する文字列
  -----------------------------------------------*/
void char_to_hash(unsigned char *hash, const char* id){
    SHA256(id,strlen(id),hash);
    /* --- debug print --- */
    print_unsigned_char(hash, "hash", SHA256_DIGEST_LENGTH);
}

/* -----------------------------------------------
 * 排他的論理和を計算する関数
 * $0 計算結果を入れるu_char配列ポインタ
 * $1 XORする値
 * $2 平文/暗号化文
 * $3 ハッシュの文字数
 * $4 テキストの文字数
 -----------------------------------------------*/
void exclusive_disjunction(unsigned char *ciphertext, const unsigned char *hash,
                           const char *text, const size_t hashSize, const size_t textSize) {
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
 -----------------------------------------------*/
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size){
    printf("\x1b[32m%s = \x1b[39m", dataName);
    for (size_t i=0; i<size; i++){
        printf("%02x", uc[i] );
    }
    printf("\n");
}

/* -----------------------------------------------
 * 文字列を緑色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_green_color(const char *text) {
    printf("\x1b[32m%s\x1b[39m", text);
}
