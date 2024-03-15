package schnorr;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import crypt_basics.hash.Hash;

/**
 * Schnorr signature
 * 
 * @see <a href="https://en.wikipedia.org/wiki/Schnorr_signature">Schnorr
 *      signature</a>
 */
public class Schnorr {

    /**
     * Schnorr group (p, q, g)
     */
    public class SchnorrGroup implements Comparable<SchnorrGroup> {
        public final BigInteger p;
        public final BigInteger q;
        public final BigInteger g;

        /**
         * Schnorr group (p, q, g)
         * 
         * @param p prime number p
         * @param q prime number q
         * @param g generator g
         */
        public SchnorrGroup(BigInteger p, BigInteger q, BigInteger g) {
            this.p = p;
            this.q = q;
            this.g = g;
        }

        @Override
        public int compareTo(SchnorrGroup arg0) {
            return q.compareTo(arg0.q);
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof SchnorrGroup)) {
                return false;
            }

            return q.equals(((SchnorrGroup) obj).q);
        }

        @Override
        public int hashCode() {
            return q.hashCode();
        }
    }

    /**
     * Schnorr signature (r, s)
     */
    public class SchnorrSignature {
        public final BigInteger r;
        public final BigInteger s;

        public SchnorrSignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }

    SchnorrGroup group;

    /**
     * Private key x and public key y
     */
    private BigInteger x;
    private BigInteger y;

    /**
     * Generate a Schnorr group (p, q, g) such that p = qr + 1
     * 
     * @param bitLength the bit length of the prime number p
     * @throws InterruptedException
     * 
     */
    public Schnorr(int bitLength) throws InterruptedException {
        int cores = Runtime.getRuntime().availableProcessors();

        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(cores);

        Queue<SchnorrGroup> queue = new PriorityQueue<>();

        for (int i = 0; i < cores; i++) {
            executor.execute(() -> {
                SchnorrGroup loc = generateSchnorrGroup(bitLength);

                queue.add(loc);
            });
        }

        while (null == (group = queue.poll())) {
            Thread.sleep(100);
        }

        executor.shutdown();

        generateKeyPair();

    }

    /**
     * Generate a key pair (x, y) such that y = g^x mod p
     */
    private void generateKeyPair() {
        do {
            x = new BigInteger(group.q.bitLength(), new SecureRandom());
        } while (x.compareTo(BigInteger.ONE) <= 0 || x.compareTo(group.q) >= 0);

        y = group.g.modPow(x, group.p);
    }

    /**
     * Generate a Schnorr group (p, q, g) such that p = qr + 1
     * 
     * @param bitLength
     * @return
     */
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

    public SchnorrSignature sign(byte[] message) throws NoSuchAlgorithmException {

        BigInteger k;
        BigInteger r;
        BigInteger s;

        if (group.q.bitCount() < 256) {
            throw new NoSuchAlgorithmException("The bit length of q is less than 256");
        }

        Hash hash = new Hash(256);

        BigInteger e = new BigInteger(hash.hash(message));

        do {
            /**
             * Generate a random number k such that 1 < k < q
             */
            do {
                k = new BigInteger(group.q.bitLength(), new SecureRandom());
            } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(group.q) >= 0);

            /**
             * Calculate r = g^k mod p mod q
             */
            r = group.g.modPow(k, group.p).mod(group.q);
        } while (r.equals(BigInteger.ZERO));

        s = k.subtract(x.multiply(e)).mod(group.q);

        return new SchnorrSignature(r, s);
    }

    public boolean verify(byte[] message, SchnorrSignature signature) throws NoSuchAlgorithmException {

        if (group.q.bitCount() < 256) {
            throw new NoSuchAlgorithmException("The bit length of q is less than 256");
        }

        Hash hash = new Hash(256);

        BigInteger e = new BigInteger(hash.hash(message));

        /**
         * Check if r and s are in the range [1, q - 1]
         */
        if (signature.r.compareTo(BigInteger.ZERO) <= 0 || signature.r.compareTo(group.q) >= 0
                || signature.s.compareTo(BigInteger.ZERO) <= 0 || signature.s.compareTo(group.q) >= 0) {
            return false;
        }

        /**
         * Check if g^s * y^e mod p mod q = r
         */
        BigInteger v = group.g.modPow(signature.s, group.p).multiply(y.modPow(e, group.p)).mod(group.p).mod(group.q);

        return v.equals(signature.r);
    }
}