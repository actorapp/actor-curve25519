package im.actor.crypto;

import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.hmac.HMAC;
import im.actor.crypto.search.SearchableHashedWord;
import im.actor.crypto.search.SearchableWordDigest;
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
        byte[] keySecret = new byte[32];
        secureRandom.nextBytes(secret);
        secureRandom.nextBytes(keySecret);

        SearchableWordDigest searchableWordDigest = SearchableWordDigest.DEFAULT();

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

            SearchableHashedWord word = new SearchableHashedWord(b, wordKey(keySecret, b));

            byte[] r = new byte[20];
            secureRandom.nextBytes(r);
            byte[] storedWord = searchableWordDigest.digest(word, r);
            indexedWords.add(storedWord);

            if (!searchableWordDigest.compare(storedWord, word)) {
                throw new RuntimeException();
            }
        }

        // Searching
        SearchableHashedWord queryWord = new SearchableHashedWord(encQuery, wordKey(keySecret, encQuery));
        boolean isFound = false;
        for (int i = 0; i < indexedWords.size(); i++) {
            if (searchableWordDigest.compare(indexedWords.get(i), queryWord)) {
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
}