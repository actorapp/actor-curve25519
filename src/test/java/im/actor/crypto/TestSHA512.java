package im.actor.crypto;

import im.actor.crypto.primitives.digest.SHA512Digest;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TestSHA512 {
    private static String[] messages = {
            "",
            "a",
            "abc",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    };

    private static String[] digests = {
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
    };

    // 1 million 'a'
    static private String million_a_digest = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

    @Test
    public void testSHA512() {
        SHA512Digest sha512Digest = new SHA512Digest();
        for (int i = 0; i < messages.length; i++) {
            byte[] dest = new byte[64];
            byte[] data = messages[i].getBytes();
            sha512Digest.reset();
            sha512Digest.update(data, 0, data.length);
            sha512Digest.doFinal(dest, 0);
            byte[] dest2 = new byte[64];
            for (int j = 0; j < 64; j++) {
                String dg = digests[i].charAt(j * 2) + "" + digests[i].charAt(j * 2 + 1);
                dest2[j] = (byte) Integer.parseInt(dg, 16);
            }
            assertArrayEquals(dest2, dest);
        }
    }
}
