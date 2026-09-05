package com.yaravaleria.xyz.security_app.service;

import org.springframework.stereotype.Service;

@Service
public class ICService {
    private static final int ALPHABET_SIZE = 27;

    public double calculateIC(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }

        int[] frequences = new int[ALPHABET_SIZE];
        int total = text.length();

        for (char letter : text.toCharArray()) {
            int index = getIndex(letter);

            if (index >= 0) {
                frequences[index]++;
            }
        }

        if (total < 2) {
            return 0.0;
        }

        long sum = 0;

        for (int freq : frequences) {
            sum += (long) freq * (freq - 1);
        }

        return (double) sum / (total * (total - 1));
    }

    private int getIndex(char letter) {
        return "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ".indexOf(letter);
    }

    public String diagnose(double ic) {
        if (ic >= 0.060) {
            return "El texto cifrado es compatible con un cifrado monoalfabético.";
        } else if (ic >= 0.035 && ic <= 0.050) {
            return "El texto cifrado es compatible con un cifrado polialfabético.";
        } else {
            return "No se puede determinar el tipo de cifrado.";
        }
    }
}
