package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public class VigenereCipher {
    public String encrypt(String text, String key, Language language) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("La clave no puede estar vacia.");
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
                int encryptedPosition = Math.floorMod(position + keyPosition, alphabetSize);

                result.append(alphabet.charAt(encryptedPosition));
                keyIndex++;
            }
        }

        return result.toString();
    }

    private String normalizeKey(String key, String alphabet) {
        StringBuilder normalizedKey = new StringBuilder();

        for (char letter : key.toUpperCase().toCharArray()) {
            if (alphabet.indexOf(letter) >= 0) {
                normalizedKey.append(letter);
            }
        }

        if (normalizedKey.isEmpty()) {
            throw new IllegalArgumentException("La clave no contiene letras válidas del alfabeto.");
        }

        return normalizedKey.toString();
    }
}
