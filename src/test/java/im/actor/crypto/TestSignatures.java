package im.actor.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class TestSignatures {

    @Test
    public void testRandomSignatures() {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 1000; i++) {
            byte[] randomBytes = new byte[32];
            random.nextBytes(randomBytes);
            Curve25519KeyPair aliceKey = Curve25519.keyGen(randomBytes);
            byte[] message = new byte[64];
            random.nextBytes(message);
            byte[] randomBytes2 = new byte[64];
            random.nextBytes(randomBytes2);


            byte[] signature = Curve25519.calculateSignature(randomBytes2, aliceKey.getPrivateKey(), message);

            assertTrue(Curve25519.verifySignature(aliceKey.getPublicKey(), message, signature));
        }
    }
}
