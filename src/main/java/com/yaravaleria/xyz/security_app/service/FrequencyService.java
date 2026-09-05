package com.yaravaleria.xyz.security_app.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.yaravaleria.xyz.security_app.crypto.CipherAlphabet;
import com.yaravaleria.xyz.security_app.enums.Language;

@Service
public class FrequencyService {
    public List<FrequencyResult> calculateFrequencies(String text, Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        int[] freq = new int[alphabet.length()];
        int total = text != null ? text.length() : 0;

        if (text == null || text.isEmpty()) {
            return createResults(alphabet, freq, 0);
        }

        for (char letter : text.toCharArray()) {
            int index = alphabet.indexOf(letter);

            if (index >= 0) {
                freq[index]++;
            }
        }

        return createResults(alphabet, freq, total);
    }

    private List<FrequencyResult> createResults(String alphabet, int[] freq, int total) {
        List<FrequencyResult> results = new ArrayList<>();

        for (int i = 0; i < alphabet.length(); i++) {
            double percentage = total > 0 ? (freq[i] * 100.0) / total : 0.0;
            results.add(new FrequencyResult(String.valueOf(alphabet.charAt(i)), freq[i], percentage));
        }

        return results;
    }

    public record FrequencyResult(String letter, int count, double percentage) {
    }
}
