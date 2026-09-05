package com.yaravaleria.xyz.security_app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.yaravaleria.xyz.security_app.dto.RegisterRequest;
import com.yaravaleria.xyz.security_app.service.UserService;

@Controller
public class AuthController {
    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("registerRequest", new RegisterRequest());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute RegisterRequest request, Model model) {
        try {
            userService.registerUser(request);
            return "redirect:/login";
        } catch (IllegalArgumentException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("registerRequest", request);
            return "register";
        }
    }

    @GetMapping("/login")
    public String showLoginPage(
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String logout,
            Model model) {
        if (error != null) {
            model.addAttribute(
                    "error", "Nombre de usuario o contraseña incorrectos.");
        }

        if (logout != null) {
            model.addAttribute(
                    "message", "Sesión cerrada correctamente.");
        }

        return "login";
    }
}
