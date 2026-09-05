package com.yaravaleria.xyz.security_app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.yaravaleria.xyz.security_app.crypto.AffineCipher;
import com.yaravaleria.xyz.security_app.crypto.AffineDecipher;
import com.yaravaleria.xyz.security_app.crypto.CaesarCipher;
import com.yaravaleria.xyz.security_app.crypto.CaesarDecipher;
import com.yaravaleria.xyz.security_app.crypto.VigenereCipher;
import com.yaravaleria.xyz.security_app.crypto.VigenereDecipher;
import com.yaravaleria.xyz.security_app.enums.Language;
import com.yaravaleria.xyz.security_app.service.NormalizerService;

@Controller
public class CryptoController {
    private final CaesarCipher caesarCipher;
    private final CaesarDecipher caesarDecipher;
    private final AffineCipher affineCipher;
    private final AffineDecipher affineDecipher;
    private final VigenereCipher vigenereCipher;
    private final VigenereDecipher vigenereDecipher;
    private final NormalizerService normServ;

    public CryptoController() {
        this.caesarCipher = new CaesarCipher();
        this.caesarDecipher = new CaesarDecipher();
        this.affineCipher = new AffineCipher();
        this.affineDecipher = new AffineDecipher();
        this.vigenereCipher = new VigenereCipher();
        this.vigenereDecipher = new VigenereDecipher();
        this.normServ = new NormalizerService();
    }

    @GetMapping("/crypto")
    public String crypto(Model model) {
        model.addAttribute("languages", Language.values());
        return "crypto";
    }

    @PostMapping("/crypto/encrypt")
    public String encrypt(
            @RequestParam("text") String text,
            @RequestParam("language") Language language,
            @RequestParam("type") String type,
            @RequestParam(value = "key", required = false, defaultValue = "0") String key,
            @RequestParam(value = "a", required = false, defaultValue = "1") int a,
            @RequestParam(value = "b", required = false, defaultValue = "0") int b,
            Model model) {
        prepareModel(model, text, language, type);

        try {
            String normalizedText = prepareText(text, language);

            model.addAttribute("normalizedText", normalizedText);

            String result = switch (type.trim().toUpperCase()) {
                case "CAESAR" -> caesarCipher.encrypt(
                        normalizedText,
                        Integer.parseInt(key),
                        language);

                case "AFFINE" -> affineCipher.encrypt(
                        normalizedText,
                        a,
                        b,
                        language);

                case "VIGENERE" -> vigenereCipher.encrypt(
                        normalizedText,
                        key,
                        language);

                default -> throw new IllegalArgumentException(
                        "El tipo de cifrado seleccionado no es válido.");
            };

            model.addAttribute("result", result);
            model.addAttribute("operation", "Cifrado");

        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
        }

        return "crypto";
    }

    @PostMapping("/crypto/decrypt")
    public String decrypt(
            @RequestParam("text") String text,
            @RequestParam("language") Language language,
            @RequestParam("type") String type,
            @RequestParam(value = "key", required = false, defaultValue = "0") String key,
            @RequestParam(value = "a", required = false, defaultValue = "1") int a,
            @RequestParam(value = "b", required = false, defaultValue = "0") int b,
            Model model) {
        prepareModel(model, text, language, type);

        try {
            String normalizedText = prepareText(text, language);

            model.addAttribute("normalizedText", normalizedText);

            String result = switch (type.trim().toUpperCase()) {
                case "CAESAR" -> caesarDecipher.decrypt(
                        normalizedText,
                        Integer.parseInt(key),
                        language);

                case "AFFINE" -> affineDecipher.decrypt(
                        normalizedText,
                        a,
                        b,
                        language);

                case "VIGENERE" -> vigenereDecipher.decrypt(
                        normalizedText,
                        key,
                        language);

                default -> throw new IllegalArgumentException(
                        "El tipo de descifrado seleccionado no es válido.");
            };

            model.addAttribute("result", result);
            model.addAttribute("operation", "Descifrado");

        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
        }

        return "crypto";
    }

    private String prepareText(String text, Language language) {
        if (text == null || text.trim().length() < 400) {
            throw new IllegalArgumentException(
                    "El texto debe contener al menos 400 caracteres.");
        }

        if (language.name().equals("ENGLISH")
                && (text.contains("Ñ") || text.contains("ñ"))) {

            throw new IllegalArgumentException(
                    "El idioma inglés no permite utilizar la letra Ñ.");
        }

        String normalizedText = normServ.normalize(text, language);

        if (normalizedText.isEmpty()) {
            throw new IllegalArgumentException(
                    "El texto no contiene caracteres válidos para el idioma seleccionado.");
        }

        return normalizedText;
    }

    private void prepareModel(
            Model model,
            String text,
            Language language,
            String type) {

        model.addAttribute("languages", Language.values());
        model.addAttribute("text", text);
        model.addAttribute("language", language);
        model.addAttribute("type", type);
    }
}
