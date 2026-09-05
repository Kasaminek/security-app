package com.yaravaleria.xyz.security_app.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.yaravaleria.xyz.security_app.dto.RegisterRequest;
import com.yaravaleria.xyz.security_app.model.User;
import com.yaravaleria.xyz.security_app.repository.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User registerUser(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Ya existe un usuario con ese nombre.");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Ya existe un usuario con ese correo.");
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());

        User user = new User(request.getUsername(), request.getEmail(), encodedPassword);
        return userRepository.save(user);
    }
}
