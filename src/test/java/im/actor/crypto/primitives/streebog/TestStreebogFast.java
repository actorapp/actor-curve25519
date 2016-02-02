package im.actor.crypto.primitives.streebog;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestStreebogFast {

    @Test
    public void testFastStreebog() {
        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        byte[] data = new byte[1024];
        byte[] resFast = new byte[32];
        byte[] resSlow = new byte[32];
        StreebogFastDigest fastDigest = new StreebogFastDigest(32);
        StreebogDigest digest = new StreebogDigest(32);
        for (int i = 0; i < 1000; i++) {
            random.nextBytes(data);

            // System.out.println("===Fast");

            fastDigest.reset();
            fastDigest.update(data, 0, data.length);
            fastDigest.doFinal(resFast, 0);

            // System.out.println("===Slow");

            digest.reset();
            digest.update(data, 0, data.length);
            digest.doFinal(resSlow, 0);

            assertArrayEquals(resFast, resSlow);
        }
    }
}
