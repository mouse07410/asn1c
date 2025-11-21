# GitHub Copilot Instructions for asn1c

This document provides comprehensive guidance for GitHub Copilot when working on the **asn1c** (ASN.1 to C compiler) project to ensure high-quality, consistent, and maintainable code contributions.

## Project Overview

**asn1c** is a sophisticated ASN.1 to C compiler that generates C++ compatible C source code for serializing and deserializing ASN.1-based data formats. This is a mature, production-grade project with complex parsing, code generation, and encoding/decoding capabilities.

### Key Technologies
- **Languages**: C (C90/C99), with generated code compatible with C++
- **Build System**: GNU Autotools (autoconf/automake)
- **Standards**: ASN.1, BER/DER, PER, OER, XER, JER encoding standards
- **Target Domains**: PKI/X.509, telecommunications, automotive (V2X), networking protocols

## Code Style and Conventions

### General C Style Guidelines
- Follow the `.clang-format` configuration (Google style base with custom modifications)
- Use 4-space indentation, no tabs
- Maximum 2 empty lines between functions
- Always break after definition return type for top-level functions
- No space before parentheses: `function()` not `function ()`
- Prefer explicit over implicit: use `!= 0` instead of implicit boolean conversion

### Naming Conventions
```c
// Functions: lowercase with underscores
int parse_asn1_module(const char *filename);

// Types: suffix with _t, use descriptive names
typedef struct asn1p_expr_s asn1p_expr_t;

// Constants: ALL_CAPS with underscores
#define ASN_STRING_MAX_SIZE 1024

// Variables: lowercase with underscores
int current_line_number;
char *module_name;
```

### Memory Management
- Always check return values of `malloc()`, `calloc()`, `strdup()`
- Use `assert()` for internal consistency checks
- Prefer stack allocation for small, fixed-size buffers
- Free memory in reverse order of allocation
- Set pointers to NULL after freeing

### Error Handling Patterns
```c
// Return -1 for errors, 0 for success, positive for specific cases
int function_name(args) {
    if(!args) return -1;
    
    // ... processing ...
    
    if(error_condition) {
        fprintf(stderr, "Error: %s\n", error_msg);
        return -1;
    }
    
    return 0;  // success
}
```

## Project Structure Understanding

### Core Components
- **asn1c/**: Main compiler executable
- **libasn1parser/**: ASN.1 syntax parser (lex/yacc based)
- **libasn1fix/**: Semantic analysis and tree transformation
- **libasn1compiler/**: Code generation engine
- **libasn1print/**: Pretty-printing utilities
- **skeletons/**: Runtime support code templates
- **tests/**: Comprehensive test suite

### Key Data Structures
- `asn1p_expr_t`: ASN.1 expression tree nodes
- `arg_t`: Compiler arguments and context
- `asn1c_ioc_table_t`: Information Object Classes
- `asn1p_constraint_t`: ASN.1 constraints

## Build and Test Requirements

### Build Process
```bash
# Initial setup (first time only)
autoreconf -iv
./configure

# Build
make

# Testing (may take several minutes)
make check
make distcheck

# For development, faster partial builds:
make -C asn1c          # build just the compiler
make -C tests/tests-asn1c-compiler check  # run specific test suite
```

### Testing Patterns
- Always add tests for new features in appropriate `tests/` subdirectory
- Use existing test patterns and naming conventions
- Test edge cases, especially for ASN.1 constraint validation
- Include both positive and negative test cases

### Test File Organization
- **tests-asn1c-compiler/**: Parser and compiler tests
- **tests-skeletons/**: Runtime library tests  
- **tests-c-compiler/**: Generated code compilation tests
- **tests-randomized/**: Fuzzing and stress tests

## Domain-Specific Knowledge

### ASN.1 Concepts to Understand
- **Types**: SEQUENCE, SET, CHOICE, INTEGER, OCTET STRING, etc.
- **Constraints**: SIZE, FROM, WITH COMPONENT, etc.
- **Encoding Rules**: BER/DER (byte-oriented), PER/UPER (bit-oriented), XER (XML)
- **Information Object Classes**: Parameterized types and constraints

### Code Generation Patterns
- Generated code follows consistent naming: `TypeName_t`, `TypeName_encode_der()`
- Runtime functions use consistent prefixes: `ber_`, `per_`, `xer_`, `oer_`, `jer_`
- Constraint validation functions: `TypeName_constraint()`

### Common ASN.1 Error Patterns to Avoid
- Incorrect tag handling in BER/DER encoding
- Buffer overflow in PER encoding/decoding
- Improper constraint validation
- Memory leaks in choice type handling

## Specific Guidelines for Contributions

### When Adding New Features
1. **Parser Changes**: Update both lexer (.l) and parser (.y) files consistently
2. **Code Generation**: Add skeleton templates in `skeletons/` if needed
3. **Encoding Support**: Implement all relevant encoding rules (BER, PER, OER, XER, JER)
4. **Documentation**: Update man pages in `doc/man/` and usage documentation

### When Fixing Bugs
1. **Reproduce First**: Add a test case that demonstrates the issue
2. **Minimal Changes**: Prefer surgical fixes over broad refactoring
3. **Regression Testing**: Ensure `make check` passes completely
4. **Edge Cases**: Consider boundary conditions and malformed input

### Code Review Checklist
- [ ] Follows existing code style and patterns
- [ ] Includes appropriate error handling
- [ ] Has corresponding test coverage
- [ ] Doesn't break existing functionality (`make check`)
- [ ] Updates documentation if changing user-facing behavior
- [ ] Uses consistent naming conventions
- [ ] Properly handles memory allocation/deallocation

## Common Pitfalls to Avoid

### Memory Management Issues
- Double-free errors (common in cleanup paths)
- Memory leaks in error conditions
- Use-after-free when sharing ASN.1 expression trees
- Buffer overruns in string manipulation

### ASN.1 Parsing Issues
- Incorrect precedence in constraint expressions
- Missing semantic validation in the fix phase
- Improper handling of forward references
- Tag conflicts in CHOICE types

### Code Generation Issues
- Inconsistent function naming in generated code
- Missing bounds checking in array access
- Incorrect handling of optional elements
- Platform-specific assumptions (endianness, integer sizes)

## Useful Debugging Techniques

### Compiler Debugging Flags
```bash
# Print ASN.1 syntax tree after parsing
asn1c -E module.asn1

# Print after semantic fixing
asn1c -E -F module.asn1

# Print generated code without saving
asn1c -P module.asn1
```

### Common Debugging Patterns
- Use `DEBUG()` macro for conditional debug output
- Add `assert()` statements for invariant checking
- Use `fprintf(stderr, ...)` for error reporting
- Enable ASN_DEBUG during development builds

## Performance Considerations

### Code Generation Efficiency
- Minimize dynamic memory allocation in generated code
- Use stack allocation for small, bounded structures
- Optimize common cases (simple INTEGER, short strings)
- Avoid redundant constraint checking

### Compilation Performance
- Cache frequently-used lookups (symbol tables)
- Minimize string copying and concatenation
- Use efficient data structures for large ASN.1 modules

## Integration with CI/CD

The project uses GitHub Actions CI that:
- Builds on Ubuntu with standard GNU toolchain
- Runs full test suite (`make check`)
- Performs distribution testing (`make distcheck`)
- Must pass before merge

Ensure all contributions:
- Build cleanly without warnings
- Pass all existing tests
- Include new tests for new functionality
- Don't break the distribution build

---

When working on this project, prioritize correctness and maintainability over clever optimizations. The ASN.1 standards are complex and subtle, so careful adherence to specifications and thorough testing are essential.