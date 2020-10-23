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

  unsigned int buf[4];
  char out[32];
  printf("%s\n", argv[1]);
  md5_custom(buf, argv[1], strlen(argv[1]));
  sprintf(out, "%08x%08x%08x%08x", __bswap_32(~buf[0]), __bswap_32(~buf[1]), __bswap_32(~buf[2]), __bswap_32(~buf[3]));
  printf("%s\n", out);

  return 0;
}
