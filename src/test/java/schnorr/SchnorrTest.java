package schnorr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

class SchnorrTest {

    @Test
    void testGenerateSchnorrGroup() {
        Schnorr schnorr = new Schnorr();
        Schnorr.SchnorrGroup schnorrGroup = schnorr.generateSchnorrGroup(256);

        assertTrue(schnorrGroup.p.isProbablePrime(100));
        assertTrue(schnorrGroup.q.isProbablePrime(100));
        assertEquals(schnorrGroup.q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE), schnorrGroup.p);
    }

    @Test
    void testGenerateSchnorrGroupGenerator() {
        Schnorr schnorr = new Schnorr();
        Schnorr.SchnorrGroup schnorrGroup = schnorr.generateSchnorrGroup(16);

        /**
         * g^q mod p = 1
         */
        assertEquals(BigInteger.ONE, schnorrGroup.g.modPow(schnorrGroup.q, schnorrGroup.p));

        /**
         * g^i mod p != 1 for 1 < i < q
         */
        for (int i = 1; i < schnorrGroup.q.intValue(); i++) {
            BigInteger g = schnorrGroup.g.modPow(BigInteger.valueOf(i), schnorrGroup.p);
            assertNotEquals(BigInteger.ONE, g);
        }

    }
}
