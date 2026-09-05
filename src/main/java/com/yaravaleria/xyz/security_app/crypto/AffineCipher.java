package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public class AffineCipher {
    public String encrypt(String text, int a, int b, Language language) {
        int alphabetSize = CipherAlphabet.size(language);

        validateA(a, language);

        b = Math.floorMod(b, alphabetSize);
        StringBuilder result = new StringBuilder();

        for (char letter : text.toCharArray()) {
            int position = CipherAlphabet.indexOf(letter, language);

            if (position >= 0) {
                int encryptedPosition = Math.floorMod((a * position) + b, alphabetSize);

                result.append(CipherAlphabet.getAlphabet(language).charAt(encryptedPosition));
            }
        }

        return result.toString();
    }

    private void validateA(int a, Language language) {
        int alphabetSize = CipherAlphabet.size(language);

        if (gcd(a, alphabetSize) != 1) {
            throw new IllegalArgumentException(
                    "El valor de 'a' debe ser coprimo con el tamaño del alfabeto.");
        }
    }

    private int gcd(int a, int b) {
        a = Math.abs(a);

        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }

        return a;
    }
}
