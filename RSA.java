import exceptions.RSAException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.logging.FileHandler;

/**
 * Created by marek on 3/11/16.
 */
public class RSA {
    //encrypted chunk may be 33 bytes long (BigInteger uses two's complement)
    private static final int ENC_CHUNK_SIZE = 33;
    private static final int MAX_CHUNK_SIZE = 31;
    private static final int MIN_CHUNK_SIZE = 1;
    private static final int BIT_LENGTH_128 = 128;
    private static final int BIT_LENGTH_16 = 16;
    private static final int PROBABILITY = 100;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger MINUS_ONE = BigInteger.valueOf(-1);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);
    private BigInteger p, q, n, phi, e, d, c;
    private static Random rnd;
    private int chunkSize = 16;

    public int getEncChunkSize() {
        return ENC_CHUNK_SIZE;
    }

    public int getMinChunkSize() {
        return MIN_CHUNK_SIZE;
    }

    public int getMaxChunkSize() {
        return MAX_CHUNK_SIZE;
    }

    public int getChunkSize() {
        return chunkSize;
    }

    public void setChunkSize(int chunkSize) {
        this.chunkSize = chunkSize;
    }

    public RSA() {
        rnd = new Random();

    }

    public String getN() throws RSAException {
        if (n == null)
            throw new RSAException("Sorry, no modulus set.");
        else
            return n.toString();
    }

    public String getE() throws RSAException {
        if (e == null)
            throw new RSAException("Sorry, no public exponent set.");
        else
            return e.toString();
    }

    public String getD() throws RSAException {
        if (d == null)
            throw new RSAException("Sorry, no private exponent set.");
        else
            return d.toString();
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    protected static BigInteger gcd(BigInteger a, BigInteger b) {
        //non-recursive implementation of the Euclidean algorithm
        while (b.compareTo(BigInteger.ZERO) != 0) {
            BigInteger tmp = a;
            a = b;
            b = tmp.mod(b);
        }

        return a;
    }

    protected static BigInteger getOddBigInteger(int numBits) {
        BigInteger oddBigInteger;

        do
            oddBigInteger = new BigInteger(numBits, rnd);
        while (oddBigInteger.bitLength() != numBits && isEven(oddBigInteger));

        return oddBigInteger;
    }

    protected static boolean isEven(BigInteger n) {
        return n.mod(TWO).compareTo(BigInteger.ZERO) == 0;
    }

    protected static BigInteger getLessBigInteger(BigInteger n) {
        BigInteger lessBigInteger;

        do
            lessBigInteger = new BigInteger(n.bitLength(), rnd);
        while (lessBigInteger.compareTo(n) > 0);

        return lessBigInteger;
    }

    protected static BigInteger getPrime(int bitLength) {
        //uses a method explained and suggested by authors of RSA in the original RSA article
        //http://people.csail.mit.edu/rivest/Rsapaper.pdf

        BigInteger b = getOddBigInteger(bitLength);

        for (int k = 1; k <= PROBABILITY; k++) {
            BigInteger a = getLessBigInteger(b);

            if (gcd(a, b).compareTo(BigInteger.ONE) != 0
                    || jacobi(a, b).compareTo(jacobiRightHandSide(a, b)) != 0) {
                b = getOddBigInteger(bitLength);
                k = 1;
            }
        }

        return b;
    }

    protected static BigInteger modInverse(BigInteger a, BigInteger n) {
        //implements the extended Euclidean algorithm
        //https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

        BigInteger t = BigInteger.valueOf(0);   BigInteger r = n;
        BigInteger newT = BigInteger.ONE;       BigInteger newR = a;

        while (newR.compareTo(BigInteger.ZERO) != 0) {
            BigInteger quotient = r.divide(newR);

            BigInteger tmpT = newT;
            newT = t.subtract(quotient.multiply(newT));
            t = tmpT;

            BigInteger tmpR = newR;
            newR = r.subtract(quotient.multiply(newR));
            r = tmpR;
        }

        if (t.compareTo(BigInteger.ZERO) < 0)
            t = t.add(n);

        return t;
    }

    protected static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger m) {
        //uses fast modular exponentiation explained here:
        //https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/fast-modular-exponentiation
        //https://wisp.wikispaces.com/file/view/modpow.c

        BigInteger result = BigInteger.valueOf(1);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) {
                result = result.multiply(base).mod(m);
            }
            base = base.multiply(base).mod(m);
            exponent = exponent.shiftRight(1);
        }

        return result;
    }

    protected static BigInteger jacobi(BigInteger a, BigInteger b) {
        if (a.compareTo(BigInteger.ONE) == 0)
            return BigInteger.ONE;

        if (isEven(a))
            return jacobi(a.divide(TWO), b).multiply(jacobiEvenHelper(b));
        else
            return jacobi(b.mod(a), a).multiply(jacobiOddHelper(a, b));
    }

    protected static BigInteger jacobiRightHandSide(BigInteger a, BigInteger b) {
        //a^((b-1)/2) mod b
        BigInteger result = modPow(a, b.subtract(BigInteger.ONE).divide(TWO), b);
        if (result.compareTo(BigInteger.ONE) == 0)
            return BigInteger.ONE;
        else if (result.compareTo(b.subtract(BigInteger.ONE)) == 0)
            return MINUS_ONE;
        else
            return result;
    }

    protected static BigInteger jacobiEvenHelper(BigInteger b) {
        // -1^((b^2 - 1) / 8)
        if (isEven(b.pow(2).subtract(BigInteger.ONE).divide(EIGHT)))
            return BigInteger.ONE;
        else
            return MINUS_ONE;
    }

    protected static BigInteger jacobiOddHelper(BigInteger a, BigInteger b) {
        //-1^((a-1)*(b-1)/4
        if (isEven(a.subtract(BigInteger.ONE).multiply(b.subtract(BigInteger.ONE)).divide(FOUR)))
            return BigInteger.ONE;
        else
            return MINUS_ONE;
    }

    public void createKeyPair() {

        //1. generate p and q
        p = getPrime(BIT_LENGTH_128);
        q = getPrime(BIT_LENGTH_128);

        //2. calculate the public modulus n
        //n = p * q
        n = p.multiply(q);

        //3. calculate the Euler's totient function phi
        //this formula is shown in the original RSA article, see the getPrime method above
        //phi(n) = n - (p+q) + 1
        phi = n.subtract(p.add(q)).add(BigInteger.ONE);

        //4. generate the public encryption exponent e
        do {
            e = getPrime(BIT_LENGTH_16);
        } while (phi.mod(e).intValue() == 0);

        //5. generate the private decryption exponent d
        d = modInverse(e, phi);
    }

    public ByteArrayOutputStream encryptFile(byte[] plainText) throws RSAException, IOException {
        if(e == null)
            throw new RSAException("Public exponent is missing.");
        else if (n == null)
            throw new RSAException("Modulus is missing");

        List<byte[]> chunks = new ArrayList<>();
        byte[] chunk = new byte[chunkSize];
        int firstChunkSize = chunkSize;
        ByteArrayOutputStream cypherText = new ByteArrayOutputStream();

        //cut the plain text into equal chunks
        for (int i = plainText.length - 1, j = chunk.length - 1; i >= 0; i--, j--) {
            chunk[j] = plainText[i];

            //process the first chunk
            if (i == 0 && j != 0) {
                firstChunkSize = plainText.length % chunkSize;
                chunks.add(0, chunk);
                break;
            }

            //end of the chunk, add it among others and create a new one
            if (j == 0) {
                j = chunk.length;
                chunks.add(0, chunk);
                chunk = new byte[chunkSize];
            }
        }

        //do the encryption
        for (int i = 0; i < chunks.size(); i++) {
            //c = m^e mod n
            byte[] encryptedChunk = modPow(new BigInteger(1, chunks.get(i)), e, n).toByteArray();

            //align the encrypted chunk
            byte[] alignedEncryptedChunk = new byte[ENC_CHUNK_SIZE];
            System.arraycopy(encryptedChunk, 0, alignedEncryptedChunk,
                    alignedEncryptedChunk.length - encryptedChunk.length,
                    encryptedChunk.length);

            cypherText.write(alignedEncryptedChunk);
        }

        //append the sizes of the chunks
        cypherText.write(firstChunkSize);
        cypherText.write(chunkSize);

        return cypherText;
    }

    public ByteArrayOutputStream decryptFile(byte[] cypherText) throws RSAException, IOException {
        if (d == null)
            throw new RSAException("Private exponent is missing.");
        else if (n == null)
            throw new RSAException("Modulus is missing.");

        //byte stream of decrypted data
        ByteArrayOutputStream outputData = new ByteArrayOutputStream();

        //load the chunk sizes used during encryption
        int chunkSize = cypherText[cypherText.length - 1];
        System.out.println(chunkSize);
        int firstChunkSize = cypherText[cypherText.length - 2];
        System.out.println(firstChunkSize);

        //decrypt the incoming chunks
        for (int i = 0; i < cypherText.length - 2; i += ENC_CHUNK_SIZE) {
            byte[] encryptedChunk = new byte[ENC_CHUNK_SIZE];

            for (int j = 0; j < ENC_CHUNK_SIZE; j++) {
                encryptedChunk[j] = cypherText[i + j];
            }

            //m = c^d mod n
            byte[] decryptedChunk = modPow(new BigInteger(encryptedChunk), d, n).toByteArray();

            //process the first chunk
            if(i == 0) {
                byte[] alignedDecryptedFirstChunk = new byte[firstChunkSize];

                if (decryptedChunk.length > firstChunkSize)
                    alignedDecryptedFirstChunk = Arrays.copyOfRange(decryptedChunk, 1, decryptedChunk.length);

                else if (decryptedChunk.length < firstChunkSize)
                    System.arraycopy(decryptedChunk, 0, alignedDecryptedFirstChunk,
                            alignedDecryptedFirstChunk.length - decryptedChunk.length,
                            decryptedChunk.length);
                else
                    alignedDecryptedFirstChunk = decryptedChunk;

                outputData.write(alignedDecryptedFirstChunk);
                continue;
            }
            //process the rest of the chunks
            else {
                byte[] alignedDecryptedChunk = new byte[chunkSize];

                if (decryptedChunk.length > chunkSize)
                    alignedDecryptedChunk = Arrays.copyOfRange(decryptedChunk, 1, decryptedChunk.length);

                else if (decryptedChunk.length < chunkSize)
                    System.arraycopy(decryptedChunk, 0, alignedDecryptedChunk,
                            alignedDecryptedChunk.length - decryptedChunk.length,
                            decryptedChunk.length);
                else
                    alignedDecryptedChunk = decryptedChunk;

                outputData.write(alignedDecryptedChunk);
            }
        }
        return outputData;
    }
}