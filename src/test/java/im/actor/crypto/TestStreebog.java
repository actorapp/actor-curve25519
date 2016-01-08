package im.actor.crypto;

import im.actor.crypto.primitives.streebog.StreebogDigest;
import im.actor.crypto.tools.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TestStreebog {

    @Test
    public void testStreebog() {
        String res = "ed4bb0870f96417e2b7f8cd19a98f470467fc356ac160aeee0592ae69f912930";
        byte[] data = "Hello".getBytes();
        StreebogDigest digest = new StreebogDigest(32);
        byte[] hash = new byte[32];
        digest.update(data, 0, data.length);
        digest.doFinal(hash, 0);
        assertArrayEquals(Hex.fromHex(res), hash);
    }
}