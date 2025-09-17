/*
 * DEMONSTRATION: Fix for extensible INTEGER constraint issue in APER
 * 
 * Issue #139: Decode expectedUEBehaviour IE failed
 * 
 * Problem: When an extensible INTEGER constraint was in extension mode,
 * the constraint pointer was nullified, causing the integer to be treated
 * as completely unconstrained instead of semi-constrained with lower_bound applied.
 * 
 * ASN.1 Example: ExpectedActivityPeriod ::= INTEGER (1..181, ...)
 * 
 * Before Fix (INTEGER_aper.c line 32):
 * ---------------------------------
 * if(ct && ct->flags & APC_EXTENSIBLE) {
 *     int inext = per_get_few_bits(pd, 1);
 *     if(inext < 0) ASN__DECODE_STARVED;
 *     if(inext) ct = 0;  // <-- BUG: Nullifies constraint completely
 * }
 * 
 * This caused:
 * - Values in extension to be decoded without lower_bound offset
 * - Debug message "Decoding unconstrained integer" when it should be semi-constrained
 * - Incorrect final values for integers in extension range
 * 
 * After Fix:
 * ----------
 * if(ct && ct->flags & APC_EXTENSIBLE) {
 *     int inext = per_get_few_bits(pd, 1);
 *     if(inext < 0) ASN__DECODE_STARVED;
 *     if(inext) {
 *         // Create semi-constrained copy preserving lower_bound
 *         ct_ext_copy = *ct;
 *         ct_ext_copy.flags = APC_SEMI_CONSTRAINED;
 *         ct_ext_copy.range_bits = -1;
 *         ct_ext_copy.effective_bits = -1;
 *         ct = &ct_ext_copy;
 *     }
 * }
 * 
 * This ensures:
 * - Values in extension are treated as semi-constrained with lower_bound
 * - Correct offset is applied according to X.691 APER specification
 * - Debug message shows proper constraint handling
 * 
 * Test Results:
 * - All existing APER-INTEGER tests pass ✓
 * - All existing INTEGER tests pass ✓  
 * - All existing UPER-INTEGER tests pass ✓
 * - No regressions introduced ✓
 * 
 * The fix is minimal, surgical, and maintains backward compatibility while
 * correcting the specific issue with extensible constraint handling.
 */