package com.yaravaleria.xyz.security_app.controller;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.yaravaleria.xyz.security_app.crypto.AffineAttack;
import com.yaravaleria.xyz.security_app.crypto.AffineAttack.AffineAttackResult;
import com.yaravaleria.xyz.security_app.crypto.CaesarAttack;
import com.yaravaleria.xyz.security_app.crypto.CaesarAttack.CaesarAttackResult;
import com.yaravaleria.xyz.security_app.crypto.VigenereAttack;
import com.yaravaleria.xyz.security_app.crypto.VigenereAttack.VigenereAttackResult;
import com.yaravaleria.xyz.security_app.enums.Language;
import com.yaravaleria.xyz.security_app.service.AffineService;
import com.yaravaleria.xyz.security_app.service.FrequencyService;
import com.yaravaleria.xyz.security_app.service.ICService;
import com.yaravaleria.xyz.security_app.service.NormalizerService;

import jakarta.servlet.http.HttpSession;

@Controller
public class DashboardController {
    private final NormalizerService normaServ;
    private final ICService icServ;
    private final FrequencyService freqServ;
    private final AffineService affServ;

    private final CaesarAttack caeAtk;
    private final AffineAttack affAtk;
    private final VigenereAttack vigAtk;

    public DashboardController(NormalizerService normaServ, ICService icServ, FrequencyService freqServ,
            AffineService affServ,
            CaesarAttack caeAtk, AffineAttack affAtk, VigenereAttack vigAtk) {
        this.normaServ = normaServ;
        this.icServ = icServ;
        this.freqServ = freqServ;
        this.affServ = affServ;

        this.caeAtk = caeAtk;
        this.affAtk = affAtk;
        this.vigAtk = vigAtk;
    }

    @GetMapping("/dashboard")
    public String dashboard(
            Model model,
            Authentication authentication) {

        prepareCommonModel(model, authentication);

        return "dashboard";
    }

    /*
     * Análisis
     *
     * 1. Normalización.
     * 2. Índice de Coincidencia.
     * 3. Diagnóstico.
     * 4. Frecuencias observadas.
     * 5. Frecuencias de referencia.
     */

    @PostMapping("/analyze")
    public String analyze(@RequestParam("cipherText") String cipherText, @RequestParam("language") Language language,
            Model model, Authentication authentication, HttpSession session) {
        prepareCommonModel(model, authentication);

        model.addAttribute("cipherText", cipherText);
        model.addAttribute("language", language);

        if (cipherText == null || cipherText.trim().length() < 150) {
            model.addAttribute(
                    "error",
                    "El texto cifrado debe contener al menos 150 caracteres.");

            return "dashboard";
        }

        String normalizedText = normaServ.normalize(
                cipherText,
                language);

        if (normalizedText.isEmpty()) {
            model.addAttribute("error", "El texto cifrado no contiene letras válidas para el idioma seleccionado.");

            return "dashboard";
        }

        model.addAttribute("normalizedText", normalizedText);

        double ic = icServ.calculateIC(normalizedText);
        model.addAttribute("ic", ic);

        String diagnose = icServ.diagnose(ic);
        model.addAttribute("diagnose", diagnose);

        var freq = freqServ.calculateFrequencies(normalizedText, language);
        model.addAttribute("frequencies", freq);

        var referenceFrequencies = affServ.getReferenceFrequencies(language);
        var referenceMostFrequent = affServ.getMostFrequent(language);
        var frequencyComparison = affServ.compare(freq, language);
        model.addAttribute("referenceFrequencies", referenceFrequencies);
        model.addAttribute("referenceMostFrequent", referenceMostFrequent);
        model.addAttribute("frequencyComparison", frequencyComparison);

        session.setAttribute("cipherText", cipherText);
        session.setAttribute("normalizedText", normalizedText);
        session.setAttribute("language", language);
        session.setAttribute("ic", ic);
        session.setAttribute("diagnose", diagnose);
        session.setAttribute("frequencies", freq);
        session.setAttribute("referenceFrequencies", referenceFrequencies);
        session.setAttribute("referenceMostFrequent", referenceMostFrequent);
        session.setAttribute("frequencyComparison", frequencyComparison);

        model.addAttribute("analysisComplete", true);
        model.addAttribute("attackComplete", false);

        return "dashboard";
    }

    @PostMapping("/attack")
    public String attack(@RequestParam("attack") String attack, Model model, Authentication authentication,
            HttpSession session) {
        prepareCommonModel(model, authentication);

        String cipherText = (String) session.getAttribute("cipherText");
        String normalizedText = (String) session.getAttribute("normalizedText");
        Language language = (Language) session.getAttribute("language");
        Double ic = (Double) session.getAttribute("ic");
        String diagnose = (String) session.getAttribute("diagnose");

        if (normalizedText == null || language == null) {
            model.addAttribute("error", "Primero debes analizar un criptograma.");

            return "dashboard";
        }

        model.addAttribute("cipherText", cipherText);
        model.addAttribute("language", language);
        model.addAttribute("normalizedText", normalizedText);
        model.addAttribute("ic", ic);
        model.addAttribute("diagnose", diagnose);
        model.addAttribute("frequencies", session.getAttribute("frequencies"));
        model.addAttribute("referenceFrequencies", session.getAttribute("referenceFrequencies"));
        model.addAttribute("referenceMostFrequent", session.getAttribute("referenceMostFrequent"));
        model.addAttribute("frequencyComparison", session.getAttribute("frequencyComparison"));

        String selectedAttack = attack.trim().toUpperCase();
        model.addAttribute("attack", selectedAttack);

        String diagnosis = diagnoseAttackCompatibility(diagnose, selectedAttack);

        if (diagnosis != null) {
            model.addAttribute("error", diagnosis);
            model.addAttribute("analysisComplete", true);
            model.addAttribute("attackComplete", false);
            return "dashboard";
        }

        switch (selectedAttack) {
            case "CAESAR" -> {
                List<CaesarAttackResult> cResult = caeAtk.attack(normalizedText, language);

                model.addAttribute("caesarResults", cResult);
                model.addAttribute("attackType", "César");
            }

            case "AFFINE" -> {
                AffineAttackResult aResult = affAtk.attack(normalizedText, language);

                model.addAttribute("affineResult", aResult);
                model.addAttribute("affineCandidates", aResult.candidates());

                if (aResult.bestCandidate() != null) {
                    var best = aResult.bestCandidate();

                    model.addAttribute("bestCandidate", best);
                    model.addAttribute("bestA", best.a());
                    model.addAttribute("bestB", best.b());
                    model.addAttribute("bestPlaintext", best.plaintext());
                    model.addAttribute("bestScore", best.score());
                }

                model.addAttribute("attackType", "Afín");
            }

            case "VIGENERE" -> {
                VigenereAttackResult vResult = vigAtk.attack(normalizedText, language);
                model.addAttribute("repeatedSequences", vResult.repeatedSequences());
                model.addAttribute("keyLengthCandidates", vResult.candidates());
                model.addAttribute("vigenereCandidates", vResult.candidates());
                model.addAttribute("bestKey", vResult.key());
                model.addAttribute("bestKeyLength", vResult.keyLength());
                model.addAttribute("bestPlaintext", vResult.plaintext());
                model.addAttribute("vigenereResult", vResult);

                model.addAttribute("attackType", "Vigenère");
            }

            default -> {
                model.addAttribute("error", "El ataque seleccionado no es válido.");
                model.addAttribute("analysisComplete", true);

                return "dashboard";
            }
        }

        model.addAttribute("analysisComplete", true);
        model.addAttribute("attackComplete", true);

        return "dashboard";
    }

    private String diagnoseAttackCompatibility(String diagnose, String attack) {
        if (diagnose == null || diagnose.isBlank()) {
            return null;
        }

        boolean isMonoalphabetic = diagnose.equals("El texto cifrado es compatible con un cifrado monoalfabético.");
        boolean isPolyalphabetic = diagnose.equals("El texto cifrado es compatible con un cifrado polialfabético.");

        if (isMonoalphabetic && attack.equals("VIGENERE")) {
            return "No se encontró un descifrado confiable para este criptograma.";
        }

        if (isPolyalphabetic &&
                (attack.equals("CAESAR") || attack.equals("AFFINE"))) {
            return "No se encontró un descifrado confiable para este criptograma.";
        }

        return null;
    }

    private void prepareCommonModel(Model model, Authentication authentication) {
        model.addAttribute("username", authentication.getName());
        model.addAttribute("languages", Language.values());
    }
}
