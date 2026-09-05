package com.yaravaleria.xyz.security_app.service;

import org.springframework.stereotype.Service;

import com.yaravaleria.xyz.security_app.crypto.CipherAlphabet;
import com.yaravaleria.xyz.security_app.enums.Language;

@Service
public class NormalizerService {
    public String normalize(String text, Language language) {
        if (text == null || text.isEmpty()) {
            return "";
        }

        String alphabet = CipherAlphabet.getAlphabet(language);
        StringBuilder normalizedText = new StringBuilder();

        for (char letter : text.toUpperCase().toCharArray()) {
            letter = removeAccent(letter);

            if (alphabet.indexOf(letter) >= 0) {
                normalizedText.append(letter);
            }
        }

        return normalizedText.toString();
    }

    private char removeAccent(char letter) {
        return switch (letter) {
            case 'Á' -> 'A';
            case 'É' -> 'E';
            case 'Í' -> 'I';
            case 'Ó' -> 'O';
            case 'Ú' -> 'U';
            default -> letter;
        };
    }
}
