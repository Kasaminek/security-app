package com.yaravaleria.xyz.security_app.crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.springframework.stereotype.Component;

import com.yaravaleria.xyz.security_app.enums.Language;
import com.yaravaleria.xyz.security_app.service.AffineService;
import com.yaravaleria.xyz.security_app.service.FrequencyService;
import com.yaravaleria.xyz.security_app.service.FrequencyService.FrequencyResult;

@Component
public class AffineAttack {
        private final AffineDecipher decipher;
        private final FrequencyService freqService;
        private final AffineService affineService;

        public AffineAttack(
                        FrequencyService frequencyService,
                        AffineService affineService) {
                this.decipher = new AffineDecipher();
                this.freqService = frequencyService;
                this.affineService = affineService;
        }

        public AffineAttackResult attack(String ciphertext, Language language) {
                List<FrequencyResult> observed = freqService.calculateFrequencies(ciphertext, language);
                List<FrequencyResult> sortedObserved = observed.stream().sorted(Comparator.comparingDouble(
                                FrequencyResult::percentage).reversed()).toList();

                List<AffineService.ReferenceFrequency> reference = affineService.getMostFrequent(language);
                List<Candidate> candidates = new ArrayList<>();
                int observedLimit = Math.min(5, sortedObserved.size());
                int referenceLimit = Math.min(5, reference.size());

                for (int i = 0; i < observedLimit; i++) {
                        char cipherLetter = sortedObserved.get(i).letter().charAt(0);
                        int cipherPosition = CipherAlphabet.indexOf(cipherLetter, language);

                        if (cipherPosition < 0) {
                                continue;
                        }

                        for (int j = 0; j < referenceLimit; j++) {
                                char plainLetter = reference.get(j).letter();
                                int plainPosition = CipherAlphabet.indexOf(plainLetter, language);

                                for (int a : getValidA(language)) {
                                        int b = Math.floorMod(cipherPosition - (a * plainPosition),
                                                        CipherAlphabet.size(language));
                                        String plaintext = decipher.decrypt(ciphertext, a, b, language);
                                        double score = scoreFrequencies(plaintext, language);

                                        candidates.add(new Candidate(a, b, plaintext, score));
                                }
                        }
                }

                Candidate best = candidates.stream().max(Comparator.comparingDouble(Candidate::score))
                                .orElse(null);

                return new AffineAttackResult(best, observed, candidates);
        }

        private List<Integer> getValidA(Language language) {
                int size = CipherAlphabet.size(language);
                List<Integer> valid = new ArrayList<>();

                for (int a = 1; a < size; a++) {
                        if (gcd(a, size) == 1) {
                                valid.add(a);
                        }
                }

                return valid;
        }

        private int gcd(int a, int b) {
                while (b != 0) {
                        int temp = b;
                        b = a % b;
                        a = temp;
                }

                return Math.abs(a);
        }

        private double scoreFrequencies(String plaintext, Language language) {
                List<FrequencyResult> frequencies = freqService.calculateFrequencies(plaintext, language);
                List<AffineService.ReferenceFrequency> reference = affineService.getReferenceFrequencies(language);
                double score = 0.0;

                for (FrequencyResult observed : frequencies) {
                        char letter = observed.letter().charAt(0);
                        double expected = reference.stream().filter(ref -> ref.letter() == letter).mapToDouble(
                                        AffineService.ReferenceFrequency::percentage).findFirst().orElse(0.0);
                        double difference = observed.percentage() - expected;
                        score += difference * difference;
                }

                return -score;
        }

        public record Candidate(int a, int b, String plaintext, double score) {
        }

        public record AffineAttackResult(Candidate bestCandidate, List<FrequencyResult> observedFrequencies,
                        List<Candidate> candidates) {
        }
}
