package im.actor.crypto;

import im.actor.crypto.box.CBCHmacBox;
import im.actor.crypto.primitives.streebog.Streebog256;
import im.actor.crypto.primitives.util.ByteStrings;
import im.actor.crypto.primitives.prf.PRF;
import im.actor.crypto.primitives.aes.AESFastEngine;
import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.kuznechik.KuznechikCipher;
import im.actor.crypto.tools.Hex;
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
    public void testJSCase() {
        byte[] nonce = Hex.fromHex("D9A353FCEFBAE6211F4C6B95D990490CF58D5825862EA6FF5B9F97776E595CE96BC3B62B5526FC96B633354A1D1CE16A779AAFD829231EF2D0A7582DADB1CD42");
        byte[] ownPrivate = Hex.fromHex("E80EC0158F63384679445AB7C3B5141B765A76B36E1F379B6A94B26D4BC8A652");
        byte[] theirPublic = Hex.fromHex("D9D34ED487BD5B434EDA2EF2C283DB587C3AE7FB88405C3834D9D1A6D247145B");
        byte[] preMasterSecret = Hex.fromHex("52BDF36571D05AB439BE6CA31DDBADD27DDB7D0BF80D06B0635CFF5016215277");
        byte[] masterSecret = Hex.fromHex("61ADF80044E06000745550000226B0007754E00081EB6800E056C0009F5C00003747CC0092838800FCD8800002018000B3B5D800082A3000DB708000F760C000D06AA000ABDDBC002BEC0000D6A2A00004A07000E40A1000D3144000DAE88000746FC8003DBD82008AE88000CF44E000C851F0005349AA007E6F0000849DA000C0E72000FDF83D0065D7A0008697A000BDF82000C5BDD2005AC02000AD826000A715C000A05A8000F9541000E5454000D26DEE009D4AC00013C10000D7C30000E59648009F230800231F100003362000448B9800F34D3C00961700000DE6000032A7D40046994800B5710000DD3380005CD298006A82880007C5E000F0642000");

        byte[] ownPreMaster = Curve25519.calculateAgreement(ownPrivate, theirPublic);
        assertArrayEquals(ownPreMaster, preMasterSecret);

        PRF combinedPrf = Cryptos.PRF_SHA_STREEBOG_256();
        byte[] ownMasterSecret = combinedPrf.calculate(ownPreMaster, "master secret", nonce, 256);

        assertArrayEquals(ownMasterSecret, masterSecret);
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
        CBCHmacBox cbcHmacBox = new CBCHmacBox(new KuznechikCipher(protoKeys.getClientRussianKey()),
                new Streebog256(), protoKeys.getClientMacRussianKey());

        byte[] encrypted = cbcHmacBox.encryptPackage(ByteStrings.longToBytes(0), iv, rawData);
        byte[] data = cbcHmacBox.decryptPackage(ByteStrings.longToBytes(0), iv, encrypted);

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

        CBCHmacBox cbcHmacBox = new CBCHmacBox(new AESFastEngine(protoKeys.getClientKey()),
                new SHA256(), protoKeys.getClientMacKey());

        byte[] encrypted = cbcHmacBox.encryptPackage(ByteStrings.longToBytes(1), iv, rawData);
        byte[] data = cbcHmacBox.decryptPackage(ByteStrings.longToBytes(1), iv, encrypted);

        assertArrayEquals(data, rawData);
    }
}