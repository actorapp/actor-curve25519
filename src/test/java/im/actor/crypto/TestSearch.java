package im.actor.crypto;

import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.hmac.HMAC;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class TestSearch {

    @Test
    public void testSearch() {

        // Key For encryption
        SecureRandom secureRandom = new SecureRandom();
        byte[] secret = new byte[32];
        byte[] keySecret = new byte[16];
        secureRandom.nextBytes(secret);

        String text = "car cat money open open open open twitter honey";
        String query = "open";
        List<String> words = splitWords(text);

        // Encrypt words
        byte[] encQuery = encryptWord(secret, query);
        List<byte[]> encWords = new ArrayList<byte[]>();
        for (String s : words) {
            encWords.add(encryptWord(secret, s));
        }

        // Indexing
        List<byte[]> indexedWords = new ArrayList<byte[]>();
        for (byte[] b : encWords) {
            byte[] r = new byte[20];
            secureRandom.nextBytes(r);
            byte[] storedWord = indexWord(keySecret, b, r);
            indexedWords.add(indexWord(keySecret, b, r));
            if (!compare(wordKey(keySecret, b), b, storedWord)) {
                throw new RuntimeException();
            }
        }

        // Searching
        byte[] workKey = wordKey(keySecret, encQuery);
        boolean isFound = false;
        for (int i = 0; i < indexedWords.size(); i++) {
            if (compare(workKey, encQuery, indexedWords.get(i))) {
                if (i < 3 || i > 6) {
                    throw new RuntimeException();
                }
                isFound = true;
            }
        }
        if (!isFound) {
            throw new RuntimeException();
        }
    }

    private List<String> splitWords(String t) {
        ArrayList<String> res = new ArrayList<String>();
        for (String s : t.split(" ")) {
            res.add(s);
        }
        return res;
    }

    private byte[] encryptWord(byte[] secret, String word) {
        HMAC hmac = new HMAC(secret, new SHA256());
        byte[] data = word.getBytes();
        hmac.reset();
        hmac.update(data, 0, data.length);
        byte[] res = new byte[32];
        hmac.doFinal(res, 0);
        return res;
    }

    /**
     * Generate 16 bytes from word
     *
     * @param word for key computation
     * @return computed key
     */
    private byte[] wordKey(byte[] keySecret, byte[] word) {
        HMAC hmac = new HMAC(keySecret, new SHA256());
        hmac.update(word, 0, word.length);
        byte[] key = new byte[32];
        hmac.doFinal(key, 0);
        return key;
    }

    private boolean compare(byte[] wordKey, byte[] cipherWord, byte[] storedWord) {
        HMAC hmac = new HMAC(wordKey, new SHA256());
        byte[] tmp = new byte[32];
        for (int i = 0; i < 32; i++) {
            tmp[i] = (byte) (cipherWord[i] ^ storedWord[i]);
        }
        hmac.update(tmp, 0, 20);
        byte[] dest = new byte[32];
        hmac.doFinal(dest, 0);
        for (int i = 0; i < 12; i++) {
            if (dest[i] != tmp[i + 20]) {
                return false;
            }
        }
        return true;
    }

    private byte[] indexWord(byte[] keySecret, byte[] cipherWord, byte[] random) {
        byte[] res = new byte[32];
        for (int i = 0; i < 20; i++) {
            res[i] = random[i];
        }
        HMAC hmac = new HMAC(wordKey(keySecret, cipherWord), new SHA256());
        hmac.update(res, 0, 20);
        byte[] dest = new byte[32];
        hmac.doFinal(dest, 0);
        for (int i = 0; i < 12; i++) {
            res[i + 20] = dest[i];
        }
        for (int i = 0; i < 32; i++) {
            res[i] = (byte) (res[i] ^ cipherWord[i]);
        }
        return res;
    }
}