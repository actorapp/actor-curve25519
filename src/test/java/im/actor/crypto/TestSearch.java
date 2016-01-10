package im.actor.crypto;

import im.actor.crypto.search.SearchableDigest;
import im.actor.crypto.search.SearchableHashedWord;
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

        SearchableDigest searchableCipher = new SearchableDigest(secret, keySecret);

        String text = "car cat money open open open open twitter honey";
        String query = "open";
        List<String> words = splitWords(text);

        // Encrypt words
        List<byte[]> encWords = new ArrayList<byte[]>();
        for (String s : words) {
            byte[] r = new byte[20];
            secureRandom.nextBytes(r);
            encWords.add(searchableCipher.digest(s, r));
        }

        // Searching
        SearchableHashedWord queryWord = searchableCipher.buildWord(query);
        boolean isFound = false;
        for (int i = 0; i < encWords.size(); i++) {
            if (searchableCipher.compare(encWords.get(i), queryWord)) {
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
}