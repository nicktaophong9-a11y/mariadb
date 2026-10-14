# `-DWITH_TSAN=ON` produces a server that segfaults in the dynamic loader

**Affected:** 13.0.2 and current trunk (the file involved was added with the
vector/HNSW work; 11.8.4 does not have it)
**Impact:** ThreadSanitizer cannot be used on the server at all. No security
impact; it blocks a class of testing.

## Symptom

```
$ cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DWITH_TSAN=ON ...
$ cmake --build build-tsan --target mariadbd      # links fine
$ ./build-tsan/sql/mariadbd --version
Segmentation fault
```

No output, no TSAN diagnostic, and the same for any argument — the process dies
before the sanitizer runtime can report anything. Disabling ASLR
(`setarch -R`) does not help, and TSAN itself works in the same environment
(a two-thread test program reports its race normally), so it is specific to
this binary.

## Cause

```
#1 FVector::alloc_size(unsigned long) [clone .resolver]  sql/vector_mhnsw.cc:494
#2 elf_machine_rela (skip_ifunc=..., reloc_addr_arg=... <*ABS*@got.plt>)
#3 elf_dynamic_do_Rela
#4 _dl_relocate_object
#5 dl_main
```

`sql/bloom_filters.h` defines function-multiversioning macros:

```c
#define DEFAULT_IMPLEMENTATION    __attribute__ ((target ("default")))
#define AVX2_IMPLEMENTATION       __attribute__ ((target ("avx2,avx,fma")))
#define AVX512_IMPLEMENTATION     __attribute__ ((target ("avx512f,avx512bw")))
```

and `sql/vector_mhnsw.cc` applies them to the `FVector` helpers. GCC emits an
ifunc with a compiler-generated `.resolver`, instruments that resolver like any
other function, and the dynamic loader calls it during relocation — before
`__tsan_init()` has run. The first instrumented instruction in the resolver
jumps through an uninitialised runtime pointer.

A sanitizer must not instrument an ifunc resolver. GCC does not exclude
compiler-generated resolvers automatically, so the project has to.

## Workaround we used

```cmake
IF(WITH_TSAN)
  SET_SOURCE_FILES_PROPERTIES(vector_mhnsw.cc PROPERTIES COMPILE_OPTIONS "-fno-sanitize=thread")
ENDIF()
```

in `sql/CMakeLists.txt`. Coarse — it drops race detection for that whole
translation unit — but enough to get a working TSAN server. A narrower fix
would mark the multiversioned functions themselves, or have the macros in
`bloom_filters.h` carry `__attribute__((no_sanitize("thread")))` under
`__SANITIZE_THREAD__`. The same hazard applies to the other sanitizers that
instrument function entry.

## One more thing needed to get a TSAN server running

```
InnoDB: Cannot map innodb_buffer_pool_size_max=8388608m
InnoDB: Plugin initialization aborted with error Generic error
```

TSAN's shadow mappings leave too little address space for the default 8 TB
`innodb_buffer_pool_size_max` reservation. `--innodb-buffer-pool-size-max=256M`
is enough to start. Not a bug as such, but it will catch anyone who tries
this, and a note in the build docs would save them the hour.

With both of those, the server runs and reports races normally — which is how
report 2 was found.
