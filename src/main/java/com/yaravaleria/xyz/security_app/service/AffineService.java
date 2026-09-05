package com.yaravaleria.xyz.security_app.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.springframework.stereotype.Service;

import com.yaravaleria.xyz.security_app.crypto.CipherAlphabet;
import com.yaravaleria.xyz.security_app.enums.Language;

@Service
public class AffineService {
    private static final double[] ENGLISH_FREQUENCIES = {
            8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02,
            6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75,
            7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76,
            0.98, 2.36, 0.15, 1.97, 0.07
    };

    private static final double[] SPANISH_FREQUENCIES = {
            12.53, 1.42, 4.68, 5.86, 13.68, 0.69, 1.01,
            0.70, 6.25, 0.44, 0.02, 4.97, 3.15, 6.71, 0.17,
            8.68, 2.51, 0.88, 6.87, 7.98, 4.63, 3.93,
            0.90, 0.01, 0.22, 0.90, 0.52
    };

    public List<ReferenceFrequency> getReferenceFrequencies(Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        double[] frequencies = switch (language) {
            case SPANISH -> SPANISH_FREQUENCIES;
            case ENGLISH -> ENGLISH_FREQUENCIES;
        };

        if (alphabet.length() != frequencies.length) {
            throw new IllegalStateException(
                    "El tamaño del alfabeto no coincide con la tabla de frecuencias.");
        }

        List<ReferenceFrequency> result = new ArrayList<>();

        for (int i = 0; i < alphabet.length(); i++) {
            result.add(new ReferenceFrequency(alphabet.charAt(i), frequencies[i]));
        }

        return result;
    }

    public List<ReferenceFrequency> getMostFrequent(Language language) {
        return getReferenceFrequencies(language).stream()
                .sorted(Comparator.comparingDouble(ReferenceFrequency::percentage)
                        .reversed())
                .toList();
    }

    public List<FrequencyComparison> compare(List<FrequencyService.FrequencyResult> observed, Language language) {
        List<FrequencyService.FrequencyResult> sortedObserved = observed.stream()
                .sorted(Comparator.comparingDouble(FrequencyService.FrequencyResult::percentage).reversed()).toList();
        List<ReferenceFrequency> reference = getMostFrequent(language);
        int size = Math.min(sortedObserved.size(), reference.size());
        List<FrequencyComparison> result = new ArrayList<>();

        for (int i = 0; i < size; i++) {
            FrequencyService.FrequencyResult observedLetter = sortedObserved.get(i);
            ReferenceFrequency ref = reference.get(i);
            result.add(new FrequencyComparison(observedLetter.letter(), observedLetter.percentage(), ref.letter(),
                    ref.percentage()));
        }

        return result;
    }

    public record ReferenceFrequency(char letter, double percentage) {
    }

    public record FrequencyComparison(String observedLetter, double observedPercentage, char referenceLetter,
            double referencePercentage) {
    }
}
