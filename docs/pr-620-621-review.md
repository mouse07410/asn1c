# Parser cleanup and fixer diagnostics

Javier (@mr-j0nes) reported and supplied the original fixes in [PR #620](https://github.com/mouse07410/asn1c/pull/620) and [PR #621](https://github.com/mouse07410/asn1c/pull/621).

## Parser ownership and cleanup

The parser allocates the current module before reading its body so new
expressions can refer to that module. The body accumulator on the Bison
stack holds the declarations until the closing `END`. The final reduction
moves those declarations into the module, clears the current-module
pointer, and gives ownership to the grammar. A rejected parse can
therefore free the unfinished module after Bison unwinds its stack without
freeing any module already transferred to the grammar.

The explicit grammar rejections use Bison's abort path so it can destroy
earlier stack entries. The ENUMERATED rejection releases its own right-hand
side before aborting because Bison skips that rule during unwinding.
Both parse wrappers destroy the scanner after each parse. This releases
the scanner's buffer and start-condition stack before the next call.

`make -C libasn1parser check` covers repeated invalid input, errors in
headers and bodies, semantic rejections, completed modules before a
rejection, alternating file and buffer calls, and successful multi-module
ownership transfer. The regression also ran with LLVM 22 AddressSanitizer,
UndefinedBehaviorSanitizer, and LeakSanitizer. The supported calling pattern
is sequential because the parser and scanner use global state. This review
did not audit every grammar allocation-failure path.

## Fixer diagnostics

An incompatible printf argument can make a logger read an invalid pointer
or consume the wrong variadic argument. The fixer checks calls through
its error and debug callback fields. GCC and Clang enforce the attributes
on the fields. A typedef-only attribute was insufficient with Apple
Clang 21. The callback signature and runtime dispatch are unchanged.

The fixes supply the missing named INTEGER argument and correct the
argument types and source-line formatting across the fixer. Missing
diagnostic names have a printable fallback. The tag diagnostic resolves
an expression name only when debugging is enabled. The type-name lookup
returns NULL for unmapped values and values outside the generated table.

`make -C libasn1fix check` exercises the named INTEGER diagnostic with
debugging enabled and disabled. It also checks that valid callback calls
compile and that each callback independently rejects a format/type
mismatch. The compile checks ran under Apple Clang 21 and GCC 15.
