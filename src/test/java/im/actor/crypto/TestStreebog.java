package im.actor.crypto;

import im.actor.crypto.primitives.streebog.StreebogDigest;
import im.actor.crypto.tools.Hex;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestStreebog {

    //
    // Source: https://en.wikipedia.org/wiki/Streebog
    //

    private static String[] messages = {
            "",
            "The quick brown fox jumps over the lazy dog",
            "The quick brown fox jumps over the lazy dog."
    };

    private static String[] digests32 = {
            "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
            "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
            "36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da"
    };
    private static String[] digests64 = {
            "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
    };

    @Test
    public void testStreebog32() {
        for (int i = 0; i < messages.length; i++) {
            byte[] res = Hex.fromHexReverse(digests32[i]);
            byte[] data = messages[i].getBytes();
            StreebogDigest digest = new StreebogDigest(32);
            byte[] hash = new byte[32];
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);
            assertArrayEquals(res, hash);
        }
    }

    @Test
    public void testStreebog64() {
        for (int i = 0; i < digests64.length; i++) {
            byte[] res = Hex.fromHexReverse(digests64[i]);
            byte[] data = messages[i].getBytes();
            StreebogDigest digest = new StreebogDigest(64);
            byte[] hash = new byte[64];
            digest.update(data, 0, data.length);
            digest.doFinal(hash, 0);
            assertArrayEquals(res, hash);
        }
    }

//    @Test
//    public void testPerformance() {
//        SecureRandom random = new SecureRandom();
//        for (int i = 0; i < 10000000; i++) {
//            byte[] data = new byte[128];
//            random.nextBytes(data);
//            StreebogDigest digest = new StreebogDigest(32);
//            byte[] hash = new byte[32];
//            digest.update(data, 0, data.length);
//            digest.doFinal(hash, 0);
//        }
//        //
//    }
}