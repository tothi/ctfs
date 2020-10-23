#!/usr/bin/env python3
#

import lief

test = lief.parse("./test")

print(len(test.exported_functions))

test[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

test.add_exported_function(0x1680, "md5_custom")

test.write("libtest.so")

