package im.actor.crypto;

import im.actor.crypto.primitives.util.ByteStrings;
import im.actor.crypto.primitives.prf.PRF;
import im.actor.crypto.primitives.aes.AESFastEngine;
import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.kuznechik.KuznechikCipher;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class TestProto {
    @Test
    public void testProtoDH() {
        Curve25519 curve25519 = new Curve25519();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 1000; i++) {

            // Initial Data

            // Alice as a 'Server'
            Curve25519KeyPair aliceKey = curve25519.keyGen();
            byte[] aliceNonce = new byte[32];
            random.nextBytes(aliceNonce);
            // Bob as a 'Server'
            Curve25519KeyPair bobKey = curve25519.keyGen();
            byte[] bobNonce = new byte[32];
            random.nextBytes(bobNonce);

            // PreMasters
            byte[] alicePreMaster = curve25519.calculateAgreement(aliceKey.getPrivateKey(), bobKey.getPublicKey());
            byte[] bobPreMaster = curve25519.calculateAgreement(bobKey.getPrivateKey(), aliceKey.getPublicKey());
            assertArrayEquals(alicePreMaster, bobPreMaster);

            // Master keys
            byte[] aliceMaster = new PRF(new SHA256(), "master secret", 256).calculate(alicePreMaster, ByteStrings.merge(aliceNonce, bobNonce));
            byte[] bobMaster = new PRF(new SHA256(), "master secret", 256).calculate(bobPreMaster, ByteStrings.merge(aliceNonce, bobNonce));
            assertArrayEquals(aliceMaster, bobMaster);

            // Verify data
            byte[] aliceVerify = new PRF(new SHA256(), "client finished", 256).calculate(aliceMaster, ByteStrings.merge(aliceNonce, bobNonce));
            byte[] bobVerify = new PRF(new SHA256(), "client finished", 256).calculate(bobMaster, ByteStrings.merge(aliceNonce, bobNonce));
            assertArrayEquals(aliceVerify, bobVerify);

            // Verify Signature
            byte[] randomBytes = new byte[64];
            random.nextBytes(randomBytes);
            byte[] verifySig = curve25519.calculateSignature(randomBytes, bobKey.getPrivateKey(), bobVerify);
            assertTrue(curve25519.verifySignature(bobKey.getPublicKey(), aliceVerify, verifySig));

            // Building Parameters
            byte[] client_write_mac_key = ByteStrings.substring(aliceMaster, 0, 32);
            byte[] server_write_mac_key = ByteStrings.substring(aliceMaster, 32, 32);
            byte[] client_write_key = ByteStrings.substring(aliceMaster, 64, 32);
            byte[] server_write_key = ByteStrings.substring(aliceMaster, 96, 32);
        }
    }

    @Test
    public void testKuznechikProtoEncryption() {

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
        CBCHmacPackage cbcHmacPackage = new CBCHmacPackage(new KuznechikCipher(protoKeys.getClientKey()),
                new SHA256(), protoKeys.getClientMacKey());

        byte[] encrypted = cbcHmacPackage.encryptPackage(iv, rawData);
        byte[] data = cbcHmacPackage.decryptPackage(iv, encrypted);

        assertArrayEquals(data, rawData);
    }

    @Test
    public void testAESProtoEncryption() {

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

        byte[] encrypted = cbcHmacPackage.encryptPackage(iv, rawData);
        byte[] data = cbcHmacPackage.decryptPackage(iv, encrypted);

        assertArrayEquals(data, rawData);
    }
}