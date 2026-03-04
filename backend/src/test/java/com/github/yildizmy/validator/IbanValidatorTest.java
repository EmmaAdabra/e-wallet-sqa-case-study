package com.github.yildizmy.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IbanValidator.
 * Techniques used: Equivalence Partitioning (EP), Boundary Value Analysis (BVA).
 * Constants under test: IBAN_MIN_SIZE=15, IBAN_MAX_SIZE=34, IBAN_MODULUS=97.
 */
class IbanValidatorTest {

    private IbanValidator ibanValidator;

    @BeforeEach
    void setUp() {
        ibanValidator = new IbanValidator();
    }

    @Test
    void isValid_shouldReturnTrueForValidGermanIban() {
        // EP (valid): standard German IBAN — 22 chars, passes MOD-97 check
        assertTrue(ibanValidator.isValid("DE89370400440532013000", null));
    }

    @Test
    void isValid_shouldReturnTrueForValidUKIban() {
        // EP (valid): UK format with alphabetic BBAN — different country code, same algorithm
        assertTrue(ibanValidator.isValid("GB29NWBK60161331926819", null));
    }

    @Test
    void isValid_shouldReturnFalseForTooShortIban() {
        // BVA: 7 chars is well below IBAN_MIN_SIZE (15) — rejected by length guard immediately
        assertFalse(ibanValidator.isValid("DE89370", null));
    }

    @Test
    void isValid_shouldReturnFalseForTooLongIban() {
        // BVA: 35 chars exceeds IBAN_MAX_SIZE (34) — rejected by length guard immediately
        assertFalse(ibanValidator.isValid("A".repeat(35), null));
    }

    @Test
    void isValid_shouldReturnFalseForIbanAtMinBoundary_Invalid() {
        // BVA: exactly 15 chars (lower boundary) — passes length check but fails MOD-97
        // checksum digits "00" are never valid per the IBAN spec
        assertFalse(ibanValidator.isValid("DE00000000000AB", null));
    }

    @Test
    void isValid_shouldReturnFalseForIbanWithSpecialCharacters() {
        // EP (invalid): '@' yields Character.getNumericValue() == -1 which is < 0,
        // triggering the special-character guard inside the MOD-97 loop
        assertFalse(ibanValidator.isValid("DE89@70400440532", null));
    }

    @Test
    void isValid_shouldReturnFalseForFailedMod97Check() {
        // EP (invalid): valid length (22 chars) and valid character set, but checksum
        // digits changed to "00" — MOD-97 result is not 1, so validation fails
        assertFalse(ibanValidator.isValid("DE00370400440532013000", null));
    }

    @Test
    void isValid_shouldHandleIbanWithLeadingTrailingSpaces() {
        // EP (edge): validator trims input before processing — a valid IBAN wrapped
        // in whitespace must still return true
        assertTrue(ibanValidator.isValid("  DE89370400440532013000  ", null));
    }
}
