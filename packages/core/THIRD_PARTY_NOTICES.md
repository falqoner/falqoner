# Third-party notices

Falqoner's own code is MIT licensed. `@falqoner/core` embeds a WebAssembly
module that also contains third-party code, whose notices follow. Everything
built from core carries this file: the core package itself, the CLI through
its dependency on core, and the web app, which publishes it next to the page
with `THIRD_PARTY_LICENSES.md`, generated from the license files of the
packages it bundles.

## Falcon-1024 WebAssembly

Falqoner builds the module itself with `packages/core/falcon/build.sh`: the
Falcon-1024 C implementation below and Falqoner's own `binding.c` beside that
script, compiled with Emscripten 5.0.7 into standalone WebAssembly (95,937
bytes, SHA-256
22581da83225d4d1b7ed0647699cd33effeeb5dade4ac1cf51cbb0f101d12851). Two
builds from clean checkouts on 2026-10-01 gave identical bytes. No Emscripten
JavaScript is included; core loads the module with its own code. The linker
also takes seventeen objects from Emscripten's system libraries; they are
listed after the Emscripten license.

### Falcon-1024 C implementation

Source: https://github.com/algorand/falcon, commit
ce15e75bceb372867daf6b8e81918ab6978686eb, `README.txt`:

```text
This code is provided under the MIT license:

==========================(LICENSE BEGIN)============================
Copyright (c) 2017-2020  Falcon Project

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
===========================(LICENSE END)=============================
```

The build compiles all eleven C files at that commit, unmodified. Ten of them,
and the header files they share, carry the same MIT permission notice, naming
the Falcon Project (2017-2019). The exceptions are `deterministic.c` and
`deterministic.h`, which have no license header. They are Algorand's
deterministic-signing extension, added in commit
06b25d7bcac00793ada7224349ca20dfc0114fab, and `deterministic.c` defines the
key-generation, signing and verification functions the module uses.
`README.txt` credits the
extension to David Lazar, "with input from Chris Peikert ... and others from
Algorand, Inc." An upstream issue asks whether the Falcon Project's MIT license
covers these additions
([algorand/falcon#4](https://github.com/algorand/falcon/issues/4), open and
unanswered since 2022-01-25). A pull request adding an MIT `LICENSE` file
([algorand/falcon#11](https://github.com/algorand/falcon/pull/11)) is not
merged (both checked 2026-09-30). The extension's terms are therefore
unresolved.

### Emscripten 5.0.7

Source: https://github.com/emscripten-core/emscripten, tag 5.0.7 (commit
263db4cffa6f9fc2ec514a70abac81362ea41849), `LICENSE`:

```text
Emscripten is available under 2 licenses, the MIT license and the
University of Illinois/NCSA Open Source License.

Both are permissive open source licenses, with little if any
practical difference between them.

The reason for offering both is that (1) the MIT license is
well-known, while (2) the University of Illinois/NCSA Open Source
License allows Emscripten's code to be integrated upstream into
LLVM, which uses that license, should the opportunity arise.

The full text of both licenses follows.

==============================================================================

Copyright (c) 2010-2014 Emscripten authors, see AUTHORS file.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

==============================================================================

Copyright (c) 2010-2014 Emscripten authors, see AUTHORS file.
All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal with the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

    Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimers.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimers
    in the documentation and/or other materials provided with the
    distribution.

    Neither the names of Mozilla,
    nor the names of its contributors may be used to endorse
    or promote products derived from this Software without specific prior
    written permission. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.

==============================================================================

This program uses portions of Node.js source code located in src/library_path.js,
in accordance with the terms of the MIT license. Node's license follows:

    """
        Copyright Joyent, Inc. and other Node contributors. All rights reserved.
        Permission is hereby granted, free of charge, to any person obtaining a copy
        of this software and associated documentation files (the "Software"), to
        deal in the Software without restriction, including without limitation the
        rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
        sell copies of the Software, and to permit persons to whom the Software is
        furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in
        all copies or substantial portions of the Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
        FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
        AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
        LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
        FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
        IN THE SOFTWARE.
    """

The musl libc project is bundled in this repo, and it has the MIT license, see
system/lib/libc/musl/COPYRIGHT

The third_party/ subdirectory contains code with other licenses. None of it is
used by default, but certain options use it (e.g., the optional closure compiler
flag will run closure compiler from third_party/).
```

### Emscripten system code in the WebAssembly

The build's link record (`why-extract.txt`) names these objects from
Emscripten's prebuilt system libraries. Each is mapped by name to its source at
the Emscripten commit above, with the license statement found there. Some of
the musl files carry Emscripten's changes, marked `__EMSCRIPTEN__` or
`XXX EMSCRIPTEN`; those changes are Emscripten's, under its `LICENSE` above.

- `libc.a(emscripten_memset.o)`: `system/lib/libc/emscripten_memset.c`, which
  compiles musl's `src/string/memset.c` in this build. musl: MIT, below.
- `libc.a(__errno_location.o)`:
  `system/lib/libc/musl/src/errno/__errno_location.c`. musl: MIT, below.
- `libc.a(strcmp.o)`, `libc.a(strlen.o)`, `libc.a(strdup.o)`,
  `libc.a(stpncpy.o)`, `libc.a(strncpy.o)`: `strcmp.c`, `strlen.c`,
  `strdup.c`, `stpncpy.c` and `strncpy.c` in
  `system/lib/libc/musl/src/string/`. musl: MIT, below.
- `libc.a(abort.o)`, `libc.a(clock_gettime.o)`:
  `system/lib/libc/musl/src/exit/abort.c` and
  `system/lib/libc/musl/src/time/clock_gettime.c`. musl: MIT, below.
- `libc.a(wasi-helpers.o)`: `system/lib/libc/wasi-helpers.c`. Header: The
  Emscripten Authors, MIT or NCSA, as above.
- `libstandalonewasm-nocatch-memgrow.a(standalone.o)`:
  `system/lib/standalone/standalone.c`. Header: The Emscripten Authors, MIT or
  NCSA, as above.
- `libc.a(emscripten_memcpy.o)`, `libc.a(emscripten_memcpy_bulkmem.o)`:
  `system/lib/libc/emscripten_memcpy.c` and `emscripten_memcpy_bulkmem.S`.
  No file header. Every author in their history is listed in Emscripten's
  `AUTHORS`, which says: "Authors keep copyright of their contributions, of
  course; they just grant a license to everyone to use it as detailed in
  LICENSE." That is the `LICENSE` above.
- `libc.a(emscripten_get_heap_size.o)`, `libdlmalloc.a(sbrk.o)`:
  `system/lib/libc/emscripten_get_heap_size.c` and `system/lib/libc/sbrk.c`.
  Header: The Emscripten Authors, MIT or NCSA, as above.
- `libdlmalloc.a(dlmalloc.o)`: `system/lib/dlmalloc.c`, dlmalloc 2.8.6.
  Header: "written by Doug Lea and released to the public domain, as
  explained at http://creativecommons.org/publicdomain/zero/1.0/".
- `libcompiler_rt.a(stack_ops.o)`: `system/lib/compiler-rt/stack_ops.S`. No
  file header. Emscripten added it as `stack_ops.s` (commit
  deaa2cb4b4611fd7cdde7ba036b10cde188ff4d6) and renamed it (commit
  528a6ab880f126095ce7f21644cec085971cf90c). Its authors are listed in
  `AUTHORS`, as above. Its directory also holds LLVM's `LICENSE.TXT` (Apache
  License 2.0 with LLVM Exceptions) for the compiler-rt code that
  `system/lib/update_compiler_rt.py` imports into subdirectories. That
  script does not import this file.

musl, `system/lib/libc/musl/COPYRIGHT` at the same commit:

```text
musl as a whole is licensed under the following standard MIT license:

----------------------------------------------------------------------
Copyright © 2005-2020 Rich Felker, et al.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
----------------------------------------------------------------------
```
