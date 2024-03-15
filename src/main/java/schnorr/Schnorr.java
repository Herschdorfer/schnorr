package schnorr;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Schnorr {

    public class SchnorrGroup {
        public BigInteger p;
        public BigInteger q;
        public BigInteger g;

        public SchnorrGroup(BigInteger p, BigInteger q, BigInteger g) {
            this.p = p;
            this.q = q;
            this.g = g;
        }
    }

    SchnorrGroup generateSchnorrGroup(int bitLength) {
        BigInteger p;
        BigInteger q;

        /**
         * Generate a random prime number p and a prime number q such that p = qr + 1
         */
        do {
            p = BigInteger.probablePrime(bitLength, new SecureRandom());
            q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        } while (!q.isProbablePrime(100));

        /**
         * Generate a random number h such that 1 < h < p - 1 and h^q mod p != 1
         */
        BigInteger h;
        do {
            h = new BigInteger(p.bitLength(), new SecureRandom());
        } while (h.compareTo(BigInteger.ONE) <= 0 || h.compareTo(p.subtract(BigInteger.ONE)) >= 0
                || h.modPow(q, p).equals(BigInteger.ONE));

        /**
         * Return the Schnorr group (p, q, h)
         */
        BigInteger g = h.modPow(BigInteger.valueOf(2), p);

        return new SchnorrGroup(p, q, g);
    }
}