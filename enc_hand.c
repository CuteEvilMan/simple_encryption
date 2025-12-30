#include <errno.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
// #include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t word_t;

typedef uint8_t return_t;
const size_t IN_BUF_SIZE = 4096;
const size_t OUT_BUF_SIZE = 4096 + 16;  // 输出缓冲区稍大以防填充

struct aes_gcm_key
{
    word_t key[256 / sizeof(word_t) / 8];  // 256 bits = 32 bytes
};

struct aes_gcm_IV
{
    word_t iv[128 / sizeof(word_t) / 8];  // 128 bits = 16 bytes
};

struct aes_gcm_key_iv
{
    struct aes_gcm_key key;
    struct aes_gcm_IV iv;
};
return_t generate_aes_gcm_key_iv(struct aes_gcm_key_iv* key_iv)
{
    if (RAND_bytes((unsigned char*)key_iv, sizeof(struct aes_gcm_key_iv)) != 1)
    {
        return 1;  // failure
    }
    return 0;  // success
}

struct AAD
{
    word_t aad[512 / sizeof(word_t) / 8];  // 512 bits = 64 bytes
};

return_t generate_aes_gcm_aad(struct AAD* aad)
{
    if (RAND_bytes((unsigned char*)aad, sizeof(struct AAD)) != 1)
    {
        return 1;  // failure
    }
    return 0;  // success
}

struct aes_gcm_tag
{
    word_t tag[128 / sizeof(word_t) / 8];  // 128 bits = 16 bytes
};

static void log_openssl_err(const char* where)
{
    unsigned long e;
    while ((e = ERR_get_error()) != 0)
    {
        fprintf(stderr, "[%s] OpenSSL: %s\n", where, ERR_error_string(e, NULL));
    }
}
return_t aes256_gcm_encrypt(const struct aes_gcm_key_iv* key_iv, const struct AAD* aad,
                            FILE* in_file, FILE* out_file, struct aes_gcm_tag* tag,
                            uint64_t file_size)
{
    (void)file_size;  // 未使用
    // key ,iv , aad 的初始化处理/*  */
    const unsigned char* key = (const unsigned char*)key_iv->key.key;  // 32B
    const unsigned char* iv = (const unsigned char*)key_iv->iv.iv;     // 16B（你当前的结构）
    const int iv_len = (int)sizeof(key_iv->iv.iv);                     // 16

    // AAD
    const unsigned char* aad_data = NULL;
    int aad_len = 0;
    if (aad)
    {
        aad_data = (const unsigned char*)aad->aad;  // 64B
        aad_len = (int)sizeof(aad->aad);            // 64
    }

    /* 创建上下文：调用 EVP_CIPHER_CTX_new()，失败则退出并清理。
选择算法：用 EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) 只设定算法。
设置 IV 长度（你用 16 字节时需要显式设）：EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
iv_len,NULL)。 加入密钥和 IV：
EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)。 可选 AAD：如果有 AAD，调用一次
EVP_EncryptUpdate(ctx, NULL, &len, aad_data, aad_len) 让它参与认证。 */
    return_t ok = 0;
    int len = 0;
    unsigned char in_buf[IN_BUF_SIZE];
    unsigned char out_buf[OUT_BUF_SIZE];
    size_t r = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        log_openssl_err("EVP_CIPHER_CTX_new");
        ok = 1;
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        log_openssl_err("EVP_EncryptInit_ex(algo)");
        ok = 2;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
    {
        log_openssl_err("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
        ok = 3;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
    {
        log_openssl_err("EVP_EncryptInit_ex(key/iv)");
        ok = 4;
        goto cleanup;
    }

    if (aad_data && aad_len > 0)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad_data, aad_len) != 1)
        {
            log_openssl_err("EVP_EncryptUpdate(AAD)");
            ok = 5;
            goto cleanup;
        }
    }
    // 读取输入文件，分块加密写入输出文件
    while ((r = fread(in_buf, 1, sizeof(in_buf), in_file)) > 0)
    {
        if (EVP_EncryptUpdate(ctx, out_buf, &len, in_buf, (int)r) != 1)
        {
            log_openssl_err("EVP_EncryptUpdate(data)");
            ok = 6;
            goto cleanup;
        }

        if (fwrite(out_buf, 1, (size_t)len, out_file) != (size_t)len)
        {
            perror("fwrite(cipher)");
            ok = 7;
            goto cleanup;
        }
    }

    if (ferror(in_file))
    {
        perror("fread(plain)");
        ok = 8;
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &len) != 1)
    {
        log_openssl_err("EVP_EncryptFinal_ex");
        ok = 9;
        goto cleanup;
    }

    if (len > 0)
    {
        if (fwrite(out_buf, 1, (size_t)len, out_file) != (size_t)len)
        {
            perror("fwrite(final)");
            ok = 10;
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag->tag), tag->tag) != 1)
    {
        log_openssl_err("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        ok = 11;
        goto cleanup;
    }

cleanup:  // 清理：调用 EVP_CIPHER_CTX_free(ctx) 释放上下文。返回状态码。
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <in> <out_cipher> <out_meta>\n", argv[0]);
        return 1;
    }

    const char* in_path = argv[1];
    const char* out_cipher_path = argv[2];
    const char* out_meta_path = argv[3];

    FILE* in_file = fopen(in_path, "rb");
    if (!in_file)
    {
        perror("fopen(in)");
        return 1;
    }

    FILE* out_cipher = fopen(out_cipher_path, "wb");
    if (!out_cipher)
    {
        perror("fopen(out_cipher)");
        fclose(in_file);
        return 1;
    }

    FILE* out_meta = fopen(out_meta_path, "wb");
    if (!out_meta)
    {
        perror("fopen(out_meta)");
        fclose(in_file);
        fclose(out_cipher);
        return 1;
    }

    struct aes_gcm_key_iv key_iv;
    struct aes_gcm_tag tag;

    if (generate_aes_gcm_key_iv(&key_iv) != 0)
    {
        fprintf(stderr, "Failed to generate AES-GCM key and IV\n");
        fclose(in_file);
        fclose(out_cipher);
        fclose(out_meta);
        return 1;
    }

    /* 不使用 AAD 时传 NULL */
    const struct AAD* aad = NULL;

    const return_t rc = aes256_gcm_encrypt(&key_iv, aad, in_file, out_cipher, &tag, 0);

    fclose(in_file);
    fclose(out_cipher);

    if (rc != 0)
    {
        fprintf(stderr, "Encryption failed, code=%u\n", rc);
        fclose(out_meta);
        return 1;
    }

    /* 将 key、iv、tag 以二进制顺序写入元数据文件 */
    if (fwrite(&key_iv, 1, sizeof(key_iv), out_meta) != sizeof(key_iv) ||
        fwrite(&tag, 1, sizeof(tag), out_meta) != sizeof(tag) ||
        fwrite(&aad, 1, sizeof(struct AAD), out_meta) != sizeof(struct AAD))
    {
        perror("fwrite(meta)");
        fclose(out_meta);
        return 1;
    }

    fclose(out_meta);
    printf("Encryption done. Cipher at %s, meta at %s\n", out_cipher_path, out_meta_path);
    return 0;
}