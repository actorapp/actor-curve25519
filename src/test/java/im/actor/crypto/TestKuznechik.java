package im.actor.crypto;

import im.actor.crypto.primitives.kuznechik.KuznechikMath;
import im.actor.crypto.primitives.modes.CBCBlockCipher;
import im.actor.crypto.primitives.kuznechik.KuznechikCipher;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestKuznechik {

    @Test
    public void testEncryption() {
        byte[] key = new byte[]{
                (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF,
                (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,
                (byte) 0xFE, (byte) 0xDC, (byte) 0xBA, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10,
                (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        };

        byte[] testPlainText = new byte[]{
                (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77, (byte) 0x00,
                (byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA, (byte) 0x99, (byte) 0x88
        };

        byte[] testCipherText = new byte[]{
                (byte) 0x7F, (byte) 0x67, (byte) 0x9D, (byte) 0x90, (byte) 0xBE, (byte) 0xBC, (byte) 0x24, (byte) 0x30,
                (byte) 0x5A, (byte) 0x46, (byte) 0x8D, (byte) 0x42, (byte) 0xB9, (byte) 0xD4, (byte) 0xED, (byte) 0xCD
        };

        KuznechikCipher cipher = new KuznechikCipher(key);
        byte[] encText = new byte[16];
        byte[] decText = new byte[16];
        cipher.encryptBlock(testPlainText, 0, encText, 0);
        cipher.decryptBlock(encText, 0, decText, 0);

        assertArrayEquals(encText, testCipherText);
        assertArrayEquals(decText, testPlainText);
    }

    @Test
    public void testRandomEncryption() {
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < 1000; i++) {
            byte[] key = new byte[32];
            byte[] data = new byte[16];
            secureRandom.nextBytes(data);
            secureRandom.nextBytes(key);

            KuznechikCipher cipher = new KuznechikCipher(key);
            byte[] encText = new byte[16];
            byte[] decText = new byte[16];
            cipher.encryptBlock(data, 0, encText, 0);
            cipher.decryptBlock(encText, 0, decText, 0);

            assertArrayEquals(decText, data);
        }
    }

    @Test
    public void testBCBEncryption() throws IntegrityException {
        for (int i = 0; i < 1000; i++) {
            SecureRandom secureRandom = new SecureRandom();
            byte[] key = new byte[32];
            byte[] data = new byte[1024];
            byte[] iv = new byte[16];
            secureRandom.nextBytes(data);
            secureRandom.nextBytes(key);
            secureRandom.nextBytes(iv);

            CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(new KuznechikCipher(key));
            byte[] encrypted = cbcBlockCipher.encrypt(iv, data);
            byte[] decrypted = cbcBlockCipher.decrypt(iv, encrypted);

            assertArrayEquals(decrypted, data);
        }
    }

    @Test
    public void testCustomMulGF256() {
        for (int i = 0; i < 255; i++) {
            for (int j = 0; j < 255; j++) {
                byte r1 = KuznechikMath.kuz_mul_gf256((byte) j, (byte) i);
                byte r2 = KuznechikMath.kuz_mul_gf256_fast((byte) j, (byte) i);
                if (r1 != r2) {
                    System.out.println(Integer.toHexString(j & 0xFF) + " * " + Integer.toHexString(i & 0xFF) + " = {" + Integer.toHexString(r1 & 0xFF) + ", " + Integer.toHexString(r2 & 0xFF) + "}");
                    throw new RuntimeException();
                }
            }
        }
    }
}
