# Third-party notices

This web app bundles third-party packages. `THIRD_PARTY_LICENSES.md`, next
to this file, is generated when the app is built, from each bundled package's
own license metadata and files. Falqoner's own code is MIT licensed.

One bundled package, `falcon-1024`, contains code whose notices the package
itself does not carry. They follow.

## falcon-1024 0.2.0

- Package: https://registry.npmjs.org/falcon-1024/-/falcon-1024-0.2.0.tgz
  (sha512-zKBiKGbAVmROFJNjy1iZ009V9wclL9lZkRAP7l7cfsHkZg14jyWgJk1XtAnmn2sxaKv2hsRTEVuTot/CSoQnSw==)
- Source: https://github.com/joe-p/falcon-1024-ts, commit
  4754f0a0ce0a3e11d4e3d7432fcbc434ebeac6ef (version 0.2.0)
- License: none declared. The package has no license field or license file,
  and its source repository has no license file (checked 2026-09-30).

It embeds a WebAssembly build of the Falcon-1024 C implementation below,
compiled with Emscripten 5.0.7, and Emscripten's JavaScript runtime. On
2026-09-30 Falqoner rebuilt it from the commits named here with the package's
own build script and got byte-identical WebAssembly (95,438 bytes, SHA-256
5c416483f859809e9fb90b483c43785cf28170ba52d4de7cfbf956bc69665a9a). The
rebuild shows where the code came from; it does not supply the package's
missing license. The linker also takes eight objects from Emscripten's system
libraries; they are listed after the Emscripten license.

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

The package's build compiles all eleven C files at that commit. Ten of them,
and the header files they share, carry the same MIT permission notice, naming
the Falcon Project (2017-2019). The exceptions are `deterministic.c` and
`deterministic.h`, which have no license header. They are Algorand's
deterministic-signing extension, added in commit
06b25d7bcac00793ada7224349ca20dfc0114fab, and `deterministic.c` defines the
key-generation, signing and verification functions the package exports.
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

The rebuild's link record names these objects from Emscripten's prebuilt
system libraries. Each is mapped by name to its source at the Emscripten commit
above, with the license statement found there:

- `libc.a(emscripten_memset.o)`: `system/lib/libc/emscripten_memset.c`, which
  compiles musl's `src/string/memset.c` in this build. musl: MIT, below.
- `libc.a(__errno_location.o)`:
  `system/lib/libc/musl/src/errno/__errno_location.c`. musl: MIT, below.
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
