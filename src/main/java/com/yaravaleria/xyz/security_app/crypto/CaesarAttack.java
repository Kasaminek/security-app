package com.yaravaleria.xyz.security_app.crypto;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import com.yaravaleria.xyz.security_app.enums.Language;

@Component
public class CaesarAttack {
    private final CaesarDecipher decipher;

    public CaesarAttack() {
        this.decipher = new CaesarDecipher();
    }

    public List<CaesarAttackResult> attack(String cipherText, Language language) {
        int alphabetSize = CipherAlphabet.size(language);
        List<CaesarAttackResult> results = new ArrayList<>();

        for (int key = 0; key < alphabetSize; key++) {
            String plainText = decipher.decrypt(cipherText, key, language);
            results.add(new CaesarAttackResult(key, plainText));
        }

        return results;
    }

    public record CaesarAttackResult(int key, String plainText) {
    }
}
