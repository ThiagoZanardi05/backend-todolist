package com.pin.config;

import com.pin.entities.UserEntity;
import com.pin.exception.UserNotFoundException;
import com.pin.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired // Injete o JwtUtil agora que é um componente
    private JwtUtil jwtUtil;

    public String authenticate(String username, String password) {
        log.info("Attempting authentication for user: {}", username);
        try {
            log.debug("Searching for user by username...");
            UserEntity user = userService.findByUsername(username);
            log.info("User found: {}", user.getUsername());

            log.debug("Checking password match...");
            boolean passwordMatches = passwordEncoder.matches(password, user.getPassword());
            log.info("Password matches: {}", passwordMatches);

            if (passwordMatches) {
                log.info("Authentication successful for user: {}", username);
                // Use a instância injetada de JwtUtil
                return jwtUtil.generateToken(username, user.getRole());
            } else {
                log.warn("Invalid credentials provided for user: {}", username);
                throw new RuntimeException("Credenciais inválidas");
            }
        } catch (UserNotFoundException e) {
            log.warn("User not found during authentication: {}", username);
            throw new RuntimeException("Credenciais inválidas");
        } catch (RuntimeException e) {
            // Já logado dentro do método JwtUtil se for erro de decodificação
            log.error("Authentication failed for user {}: {}", username, e.getMessage());
            // Re-lança a exceção original (ou uma mais genérica para o frontend)
            throw e;
        } catch (Exception e) {
            // Captura outros erros inesperados
            log.error("Unexpected error during authentication for user: {}", username, e);
            throw new RuntimeException("Erro interno durante a autenticação");
        }
    }
}