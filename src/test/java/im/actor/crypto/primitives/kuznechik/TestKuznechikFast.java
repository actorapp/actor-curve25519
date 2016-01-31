package im.actor.crypto.primitives.kuznechik;

import im.actor.crypto.primitives.util.Pack;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestKuznechikFast {

    @Test
    public void testKey() {
        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        for (int j = 0; j < 1000; j++) {
            byte[] key = new byte[32];
            random.nextBytes(key);

            KuzIntKey key1 = KuznechikCipher.convertKey(key);
            int[][] key2 = KuznechikFastEngine.convertKey(key);
            for (int i = 0; i < 10; i++) {
                for (int k = 0; k < 4; k++) {
                    assertEquals(key2[i][k], Pack.bigEndianToInt(key1.getK()[i].getB(), k * 4));
                }
            }
        }
    }

    @Test
    public void testKuz() {
        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        for (int j = 0; j < 100; j++) {
            byte[] key = new byte[32];

            random.nextBytes(key);

            KuznechikCipher slowCipher = new KuznechikCipher(key);
            KuznechikFastEngine fastCipher = new KuznechikFastEngine(key);

            byte[] data = new byte[16];
            byte[] data2 = new byte[16];
            byte[] data3 = new byte[16];
            byte[] data4 = new byte[16];
            byte[] data5 = new byte[16];
            for (int i = 0; i < 100; i++) {
                random.nextBytes(data);
                fastCipher.encryptBlock(data, 0, data2, 0);
                slowCipher.encryptBlock(data, 0, data5, 0);
                slowCipher.decryptBlock(data2, 0, data3, 0);
                fastCipher.decryptBlock(data2, 0, data4, 0);
                // slowCipher.decryptBlock(data2, 0, data4, 0);

                assertArrayEquals(data, data3);
                assertArrayEquals(data, data4);
                assertArrayEquals(data2, data5);
            }
        }
    }
}
