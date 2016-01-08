package im.actor.crypto;

import im.actor.crypto.primitives.hmac.HMAC;
import im.actor.crypto.primitives.streebog.Streebog256;
import im.actor.crypto.primitives.util.ByteStrings;
import im.actor.crypto.primitives.prf.PRF;
import im.actor.crypto.primitives.aes.AESFastEngine;
import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.kuznechik.KuznechikCipher;
import org.junit.Test;

import java.security.SecureRandom;

import static im.actor.crypto.primitives.util.ByteStrings.merge;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TestProto {
    @Test
    public void testProtoDH() {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 1000; i++) {

            // Initial Data

            // Alice as a 'Server'
            byte[] randomBytes = new byte[32];
            random.nextBytes(randomBytes);
            Curve25519KeyPair aliceKey = Curve25519.keyGen(randomBytes);
            byte[] aliceNonce = new byte[32];
            random.nextBytes(aliceNonce);
            // Bob as a 'Server'
            random.nextBytes(randomBytes);
            Curve25519KeyPair bobKey = Curve25519.keyGen(randomBytes);
            byte[] bobNonce = new byte[32];
            random.nextBytes(bobNonce);

            // PreMasters
            byte[] alicePreMaster = Curve25519.calculateAgreement(aliceKey.getPrivateKey(), bobKey.getPublicKey());
            byte[] bobPreMaster = Curve25519.calculateAgreement(bobKey.getPrivateKey(), aliceKey.getPublicKey());
            assertArrayEquals(alicePreMaster, bobPreMaster);

            // Master keys
            PRF prfCombined = Cryptos.PRF_SHA_STREEBOG_256();
            byte[] aliceMaster = prfCombined.calculate(alicePreMaster, "master secret", merge(aliceNonce, bobNonce), 256);
            byte[] bobMaster = prfCombined.calculate(bobPreMaster, "master secret", merge(aliceNonce, bobNonce), 256);
            assertEquals(aliceMaster.length, 256);
            assertEquals(bobMaster.length, 256);
            assertArrayEquals(aliceMaster, bobMaster);

            // Verify data
            byte[] aliceVerify = prfCombined.calculate(aliceMaster, "client finished", merge(aliceNonce, bobNonce), 256);
            byte[] bobVerify = prfCombined.calculate(bobMaster, "client finished", merge(aliceNonce, bobNonce), 256);
            assertArrayEquals(aliceVerify, bobVerify);

            // Verify Signature
            byte[] randomBytes2 = new byte[64];
            random.nextBytes(randomBytes2);
            byte[] verifySig = Curve25519.calculateSignature(randomBytes2, bobKey.getPrivateKey(), bobVerify);
            assertTrue(Curve25519.verifySignature(bobKey.getPublicKey(), aliceVerify, verifySig));
        }
    }

    @Test
    public void testKuznechikProtoEncryption() throws IntegrityException {

        // Master key of a connection
        SecureRandom random = new SecureRandom();
        byte[] masterKey = new byte[256];
        random.nextBytes(masterKey);
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        ActorProtoKey protoKeys = new ActorProtoKey(masterKey);

        // Package (client->server)
        byte[] rawData = "Hey! Let's encrypt!".getBytes();

        // Kuznechik level
        CBCHmacPackage cbcHmacPackage = new CBCHmacPackage(new KuznechikCipher(protoKeys.getClientRussianKey()),
                new Streebog256(), protoKeys.getClientMacRussianKey());

        byte[] encrypted = cbcHmacPackage.encryptPackage(0, iv, rawData);
        byte[] data = cbcHmacPackage.decryptPackage(0, iv, encrypted);

        assertArrayEquals(data, rawData);
    }

    @Test
    public void testAESProtoEncryption() throws IntegrityException {

        // Master key of a connection
        SecureRandom random = new SecureRandom();
        byte[] masterKey = new byte[256];
        random.nextBytes(masterKey);
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        ActorProtoKey protoKeys = new ActorProtoKey(masterKey);

        // Package (client->server)
        byte[] rawData = "Hey! Let's encrypt!".getBytes();

        CBCHmacPackage cbcHmacPackage = new CBCHmacPackage(new AESFastEngine(protoKeys.getClientKey()),
                new SHA256(), protoKeys.getClientMacKey());

        byte[] encrypted = cbcHmacPackage.encryptPackage(1, iv, rawData);
        byte[] data = cbcHmacPackage.decryptPackage(1, iv, encrypted);

        assertArrayEquals(data, rawData);
    }
}