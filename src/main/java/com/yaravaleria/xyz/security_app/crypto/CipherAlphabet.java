package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public final class CipherAlphabet {
    public static final String SPANISH_ALPHABET = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
    public static final String ENGLISH_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private CipherAlphabet() {
    }

    public static String getAlphabet(Language language) {
        return switch (language) {
            case SPANISH -> SPANISH_ALPHABET;
            case ENGLISH -> ENGLISH_ALPHABET;
        };
    }

    public static int size(Language language) {
        return getAlphabet(language).length();
    }

    public static int indexOf(char letter, Language language) {
        return getAlphabet(language).indexOf(letter);
    }

    public static char charAt(int index, Language language) {
        return getAlphabet(language).charAt(index);
    }
}
