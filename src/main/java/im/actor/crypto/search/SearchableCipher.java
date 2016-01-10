package im.actor.crypto.search;

public class SearchableCipher {

    // Source: Distinct word length frequencies: distributions and symbol entropies, 2012
    // Reginald Smith, Rochester, NY
    // http://arxiv.org/pdf/1207.2334.pdf;
    private static final int DEFAULT_MAX_LENGTH = 20;

    private int maxWordLength;

    public SearchableCipher(int maxWordLength) {
        this.maxWordLength = maxWordLength;
    }

    public SearchableCipher() {
        this(DEFAULT_MAX_LENGTH);
    }
}
