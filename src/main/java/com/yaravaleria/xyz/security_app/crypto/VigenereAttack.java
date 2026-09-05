package com.yaravaleria.xyz.security_app.crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.yaravaleria.xyz.security_app.enums.Language;
import com.yaravaleria.xyz.security_app.service.AffineService;
import com.yaravaleria.xyz.security_app.service.FrequencyService;
import com.yaravaleria.xyz.security_app.service.FrequencyService.FrequencyResult;

@Component
public class VigenereAttack {
    private final VigenereDecipher decipher;
    private final FrequencyService frequencyService;
    private final AffineService affineService;

    public VigenereAttack(FrequencyService frequencyService, AffineService affineService) {
        this.decipher = new VigenereDecipher();
        this.frequencyService = frequencyService;
        this.affineService = affineService;
    }

    public VigenereAttackResult attack(String cipherText, Language language) {
        if (cipherText == null || cipherText.isEmpty()) {
            return new VigenereAttackResult("", "", 0, List.of(), List.of());
        }

        List<RepeatedSequence> repeatedSequences = findRepeatedSequences(cipherText);
        List<Integer> distances = repeatedSequences.stream().map(RepeatedSequence::distance).toList();
        List<KeyLengthCandidate> keyLengths = findKeyLengthCandidates(
                distances,
                cipherText.length());

        if (keyLengths.isEmpty()) {
            for (int length = 1; length <= Math.min(12, cipherText.length()); length++) {
                keyLengths.add(new KeyLengthCandidate(length, 0));
            }
        }

        List<Candidate> candidates = new ArrayList<>();
        int maxLengths = Math.min(5, keyLengths.size());

        for (int i = 0; i < maxLengths; i++) {
            int keyLength = keyLengths.get(i).length();
            String key = findKey(cipherText, keyLength, language);
            String plaintext = decipher.decrypt(cipherText, key, language);
            double score = scorePlaintext(plaintext, language);
            candidates.add(new Candidate(key, keyLength, plaintext, score));
        }

        Candidate best = candidates.stream().max(Comparator.comparingDouble(Candidate::score))
                .orElse(new Candidate("", 0, "", Double.NEGATIVE_INFINITY));

        return new VigenereAttackResult(best.key(), best.plaintext(), best.keyLength(), repeatedSequences,
                candidates);
    }

    private List<RepeatedSequence> findRepeatedSequences(String text) {
        List<RepeatedSequence> result = new ArrayList<>();
        int sequenceLength = 3;
        Map<String, List<Integer>> positions = new HashMap<>();

        for (int i = 0; i <= text.length() - sequenceLength; i++) {
            String sequence = text.substring(i, i + sequenceLength);
            positions.computeIfAbsent(sequence, k -> new ArrayList<>()).add(i);
        }

        for (Map.Entry<String, List<Integer>> entry : positions.entrySet()) {
            List<Integer> sequencePositions = entry.getValue();

            if (sequencePositions.size() < 2) {
                continue;
            }

            for (int i = 0; i < sequencePositions.size() - 1; i++) {
                int first = sequencePositions.get(i);
                int second = sequencePositions.get(i + 1);
                int distance = second - first;

                result.add(new RepeatedSequence(entry.getKey(), first, second, distance));
            }
        }

        return result;
    }

    private List<KeyLengthCandidate> findKeyLengthCandidates(List<Integer> distances, int textLength) {
        Map<Integer, Integer> divisorCount = new HashMap<>();
        int maxLength = Math.min(20, textLength / 2);

        for (int distance : distances) {
            for (int divisor = 2; divisor <= maxLength; divisor++) {
                if (distance % divisor == 0) {
                    divisorCount.merge(divisor, 1, Integer::sum);
                }
            }
        }

        return divisorCount.entrySet().stream().map(entry -> new KeyLengthCandidate(entry.getKey(),
                entry.getValue())).sorted(Comparator.comparingInt(KeyLengthCandidate::votes).reversed()
                        .thenComparingInt(KeyLengthCandidate::length))
                .toList();
    }

    private String findKey(String cipherText, int keyLength, Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        StringBuilder key = new StringBuilder();

        for (int column = 0; column < keyLength; column++) {
            StringBuilder columnText = new StringBuilder();

            for (int i = column; i < cipherText.length(); i += keyLength) {
                columnText.append(cipherText.charAt(i));
            }

            int shift = findBestCaesarShift(
                    columnText.toString(),
                    language);

            key.append(alphabet.charAt(shift));
        }

        return key.toString();
    }

    private int findBestCaesarShift(String column, Language language) {
        String alphabet = CipherAlphabet.getAlphabet(language);
        int alphabetSize = alphabet.length();
        List<AffineService.ReferenceFrequency> reference = affineService.getReferenceFrequencies(language);
        int bestShift = 0;
        double bestScore = Double.POSITIVE_INFINITY;
        int total = column.length();

        if (total == 0) {
            return 0;
        }

        for (int shift = 0; shift < alphabetSize; shift++) {
            int[] observed = new int[alphabetSize];

            for (char cipherLetter : column.toCharArray()) {
                int cipherPosition = alphabet.indexOf(cipherLetter);

                if (cipherPosition < 0) {
                    continue;
                }

                int plainPosition = Math.floorMod(cipherPosition - shift, alphabetSize);

                observed[plainPosition]++;
            }

            double chiSquare = 0.0;

            for (int i = 0; i < alphabetSize; i++) {
                double expectedPercentage = reference.get(i).percentage();
                double expectedCount = (expectedPercentage / 100.0) * total;

                if (expectedCount == 0) {
                    continue;
                }

                double difference = observed[i] - expectedCount;
                chiSquare += (difference * difference) / expectedCount;
            }

            if (chiSquare < bestScore) {
                bestScore = chiSquare;
                bestShift = shift;
            }
        }

        return bestShift;
    }

    private double scorePlaintext(String plaintext, Language language) {
        List<FrequencyResult> frequencies = frequencyService.calculateFrequencies(plaintext, language);
        List<AffineService.ReferenceFrequency> reference = affineService.getReferenceFrequencies(language);
        double score = 0.0;

        for (int i = 0; i < frequencies.size(); i++) {
            double observed = frequencies.get(i).percentage();
            double expected = reference.get(i).percentage();
            double difference = observed - expected;
            score += difference * difference;
        }

        return -score;
    }

    public record RepeatedSequence(String sequence, int firstPosition, int secondPosition, int distance) {
    }

    public record KeyLengthCandidate(int length, int votes) {
    }

    public record Candidate(String key, int keyLength, String plaintext, double score) {
    }

    public record VigenereAttackResult(String key, String plaintext, int keyLength,
            List<RepeatedSequence> repeatedSequences, List<Candidate> candidates) {
    }
}
