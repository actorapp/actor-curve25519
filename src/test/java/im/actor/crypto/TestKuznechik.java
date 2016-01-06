package im.actor.crypto;

import im.actor.crypto.blocks.impl.kuznechik.Kuznechik;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

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

        byte[] encText = Kuznechik.encryptBlock(key, testPlainText);
        byte[] decText = Kuznechik.decryptBlock(key, encText);

        assertArrayEquals(encText, testCipherText);
        assertArrayEquals(decText, testPlainText);
    }
}
