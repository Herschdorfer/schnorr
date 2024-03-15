package schnorr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import schnorr.Schnorr.SchnorrSignature;

class SchnorrTest {

    @Test
    /**
     * Test the generation of the Schnorr group
     */
    void testGenerateSchnorrGroup() {
        assertDoesNotThrow(() -> {
            Schnorr schnorr = new Schnorr(256);

            assertTrue(schnorr.group.p.isProbablePrime(100));
            assertTrue(schnorr.group.q.isProbablePrime(100));
            assertEquals(schnorr.group.q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE), schnorr.group.p);
        });
    }

    @Test
    /**
     * Test the generation of the Schnorr group
     */
    void testGenerateSchnorrGroupGenerator() {
        assertDoesNotThrow(() -> {
            Schnorr schnorr = new Schnorr(16);

            /**
             * g^q mod p = 1
             */
            assertEquals(BigInteger.ONE, schnorr.group.g.modPow(schnorr.group.q, schnorr.group.p));

            /**
             * g^i mod p != 1 for 1 < i < q
             */
            for (int i = 1; i < schnorr.group.q.intValue(); i++) {
                BigInteger g = schnorr.group.g.modPow(BigInteger.valueOf(i), schnorr.group.p);
                assertNotEquals(BigInteger.ONE, g);
            }
        });
    }

    @Test
    /**
     * Test the verification of the Schnorr signature
     */
    void testVerify() {
        assertDoesNotThrow(() -> {
            Schnorr schnorr = new Schnorr(1024);

            SchnorrSignature signature = schnorr.sign("Hello, World!".getBytes());

            assertTrue(schnorr.verify("Hello, World!".getBytes(), signature));
        });

    }
}
