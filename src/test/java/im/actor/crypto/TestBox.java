package im.actor.crypto;

import im.actor.crypto.box.ActorBox;
import im.actor.crypto.box.ActorBoxKey;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestBox {

    @Test
    public void testBox() throws IntegrityException {
        SecureRandom secureRandom = new SecureRandom();
        for (int i = 0; i < 10000; i++) {
            byte[] rawKey = new byte[128];
            byte[] data = new byte[128 + secureRandom.nextInt(16)];
            byte[] header = new byte[128 + secureRandom.nextInt(16)];
            secureRandom.nextBytes(rawKey);
            secureRandom.nextBytes(data);
            secureRandom.nextBytes(header);

            ActorBoxKey key = new ActorBoxKey(rawKey);
            byte[] random32 = new byte[32];
            secureRandom.nextBytes(random32);
            byte[] box = ActorBox.closeBox(header, data, random32, key);
            byte[] res = ActorBox.openBox(header, box, key);
            assertArrayEquals(res, data);
        }
    }
}