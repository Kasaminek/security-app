package com.yaravaleria.xyz.security_app.crypto;

import com.yaravaleria.xyz.security_app.enums.Language;

public class AffineDecipher {
    public String decrypt(String text, int a, int b, Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        int alphabetSize = alphabet.length();

        validateA(a, language);

        b = Math.floorMod(b, alphabetSize);
        int inverseA = modularInverse(a, alphabetSize);
        StringBuilder result = new StringBuilder();

        for (char letter : text.toCharArray()) {
            int position = alphabet.indexOf(letter);

            if (position >= 0) {
                int decryptedPosition = Math.floorMod(
                        inverseA * (position - b),
                        alphabetSize);

                result.append(alphabet.charAt(decryptedPosition));
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

    private int modularInverse(int a, int modulus) {
        a = Math.floorMod(a, modulus);

        for (int x = 1; x < modulus; x++) {
            if ((a * x) % modulus == 1) {
                return x;
            }
        }

        throw new IllegalArgumentException(
                "No existe inversa modular para a=" + a);
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
