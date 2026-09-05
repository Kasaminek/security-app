package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public class CaesarDecipher {
    public String decrypt(String text, int key, Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        int alphabetSize = alphabet.length();
        key = Math.floorMod(key, alphabetSize);
        StringBuilder result = new StringBuilder();

        for (char letter : text.toCharArray()) {
            int position = alphabet.indexOf(letter);

            if (position >= 0) {
                int newPosition = Math.floorMod(position - key, alphabetSize);
                result.append(alphabet.charAt(newPosition));
            }
        }

        return result.toString();
    }
}
