#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint32_t lic_hash(const char *user, const char *expires) {
    uint32_t h = 0x4f5a521f;
   
    for (const char *p = user; *p != '\0'; p++) {
        h = (uint8_t)*p + h * 0x1f;
    }
   
    for (const char *p = expires; *p != '\0'; p++) {
        h = ((h ^ (uint8_t)*p) << 3) | (h >> 0x1d);
    }
   
    return h;
}

void derive_key(const char *user, const char *expires, char *out) {
    uint32_t k = lic_hash(user, expires);
   
    const unsigned char salt[] = {
        0x38, 0x1b, 0x35, 0x23, 0x39, 0x34, 0x2f, 0x1a, 0x37, 0x34, 0x1a
    };
   
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   
    for (int i = 0; i < 11; i++) {
        k = k * 0x41c64e6d + 0x3039;
        int idx = (((k >> 16) & 0xff) + salt[i]) % 0x3e;
        out[i] = alphabet[idx];
    }
    out[11] = '\0';
}

int main(void) {
    FILE *f = fopen("license.key", "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    char user[256] = {0};
    char expires[64] = {0};

    char *p = strstr(buf, "USER=");
    size_t skip = 5;
    if (!p) {
        p = strstr(buf, "NAME=");
        skip = 5;
    }
    if (p) {
        p += skip;
        while (*p == ' ' || *p == '\t') p++;
        size_t i = 0;
        while (p[i] && p[i] != '\n' && p[i] != '\r' &&
               p[i] != ' ' && p[i] != '\t' && i < sizeof(user) - 1) {
            user[i] = p[i];
            i++;
        }
        user[i] = '\0';
    }

    p = strstr(buf, "EXPIRES=");
    if (p) {
        p += 8;
        while (*p == ' ' || *p == '\t') p++;
        size_t i = 0;
        while (p[i] && p[i] != '\n' && p[i] != '\r' &&
               p[i] != ' ' && p[i] != '\t' && i < sizeof(expires) - 1) {
            expires[i] = p[i];
            i++;
        }
        expires[i] = '\0';
    }

    char key[12];
    derive_key(user, expires, key);

    f = fopen("license.key", "w");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fprintf(f, "USER=%s\n", user);
    fprintf(f, "EXPIRES=%s\n", expires);
    fprintf(f, "KEY=%s\n", key);
    fclose(f);

    printf("Key: %s\n", key);
    return 0;
}