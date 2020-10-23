#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <byteswap.h>

typedef void(*md5_custom_t)(unsigned int *, unsigned char *, long int);

int main (int argc, char** argv) {

  void* handler = dlopen("./libtest.so", RTLD_LAZY);
  if (!handler) {
    fprintf(stderr, "dlopen error: %s\n", dlerror());
    return 1;
  }
  md5_custom_t md5_custom = (md5_custom_t)dlsym(handler, "md5_custom");

  unsigned long int i;
  char in[11];
  unsigned int buf[4];
  for (i = 0; i < 1000000000; ++i) {
    sprintf(in, "%03d-%03d-%03d", i/1000000, (i/1000) % 1000, i % 1000);
    md5_custom(buf, in, 11);
    printf("%08x%08x%08x%08x:%s\n", __bswap_32(~buf[0]), __bswap_32(~buf[1]), __bswap_32(~buf[2]), __bswap_32(~buf[3]), in);
  }
  return 0;
}
