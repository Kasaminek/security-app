package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public class VigenereDecipher {
    public String decrypt(String text, String key, Language language) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("La clave no puede estar vacía.");
        }

        String alphabet = CipherAlphabet.getAlphabet(language);
        int alphabetSize = alphabet.length();
        String normalizedKey = normalizeKey(key, alphabet);
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;

        for (char letter : text.toCharArray()) {
            int position = alphabet.indexOf(letter);

            if (position >= 0) {
                char keyLetter = normalizedKey.charAt(keyIndex % normalizedKey.length());
                int keyPosition = alphabet.indexOf(keyLetter);
                int decryptedPosition = Math.floorMod(position - keyPosition, alphabetSize);

                result.append(alphabet.charAt(decryptedPosition));
                keyIndex++;
            }
        }

        return result.toString();
    }

    private String normalizeKey(String key, String alphabet) {
        StringBuilder normalized = new StringBuilder();

        for (char letter : key.toUpperCase().toCharArray()) {
            if (alphabet.indexOf(letter) >= 0) {
                normalized.append(letter);
            }
        }

        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("La clave no contiene letras válidas.");
        }

        return normalized.toString();
    }
}
