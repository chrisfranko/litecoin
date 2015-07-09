#ifndef SCRYPT_H
#define SCRYPT_H

static const int SCRYPT_SCRATCHPAD_SIZE = ((1 << (6)) * 128 ) + 63;

void scrypt_1024_1_1_256_sp(const char *input, char *output, char *scratchpad);
void scrypt_1024_1_1_256(const char *input, char *output);

#endif
