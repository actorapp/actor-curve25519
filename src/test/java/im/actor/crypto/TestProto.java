package im.actor.crypto;

import im.actor.crypto.impl.ByteStrings;
import im.actor.crypto.impl.CBCHmacPackage;
import im.actor.crypto.impl.PRF;
import im.actor.crypto.impl.bc.hash.*;
import im.actor.crypto.impl.bc.hash.SHA256;
import im.actor.crypto.impl.bc.hash.SHA512;
import im.actor.crypto.impl.kuznechik.KuznechikCipher;
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
            byte[] aliceMaster = PRF.calculate(alicePreMaster, "master secret", ByteStrings.merge(aliceNonce, bobNonce), 255,
                    new SHA256());
            byte[] bobMaster = PRF.calculate(bobPreMaster, "master secret", ByteStrings.merge(aliceNonce, bobNonce), 255,
                    new SHA256());
            assertArrayEquals(aliceMaster, bobMaster);

            // Verify data
            byte[] aliceVerify = PRF.calculate(aliceMaster, "client finished", ByteStrings.merge(aliceNonce, bobNonce), 255,
                    new SHA256());
            byte[] bobVerify = PRF.calculate(bobMaster, "client finished", ByteStrings.merge(aliceNonce, bobNonce), 255,
                    new SHA256());
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
    public void testProtoEncryption() {

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
//        byte[] kuznechik = ActorProto.createKuznechikPackage(protoKeys.getClientMacKey(), rawData);
//        ActorProto.readKuznechikPackage(protoKeys.getClientMacKey(), kuznechik);
    }
}