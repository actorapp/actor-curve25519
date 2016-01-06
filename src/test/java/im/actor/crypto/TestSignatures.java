package im.actor.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class TestSignatures {

    @Test
    public void testRandomSignatures() {
        SecureRandom random = new SecureRandom();
        Curve25519 curve25519 = new Curve25519();
        for (int i = 0; i < 1000; i++) {
            Curve25519KeyPair aliceKey = curve25519.keyGen();
            byte[] message = new byte[64];
            random.nextBytes(message);
            byte[] randomBytes = new byte[64];
            random.nextBytes(randomBytes);


            byte[] signature = curve25519.calculateSignature(randomBytes, aliceKey.getPrivateKey(), message);

            assertTrue(curve25519.verifySignature(aliceKey.getPublicKey(), message, signature));
        }
    }
}
