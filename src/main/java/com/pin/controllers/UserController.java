package com.pin.controllers;

import com.pin.entities.UserEntity;
import com.pin.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
// @CrossOrigin(origins = "http://localhost:4200") // CORS é configurado globalmente em SecurityConfig
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    // Endpoint para obter o ID local do usuário autenticado.
    // O UserService.getLoggedUserId() já usa o findOrCreateUserFromToken.
    @GetMapping("/auth/user-id")
    @PreAuthorize("isAuthenticated()") // Qualquer usuário autenticado pode acessar
    public ResponseEntity<Long> getAuthenticatedUserId() {
        try {
            return ResponseEntity.ok(userService.getLoggedUserId());
        } catch (IllegalStateException e) {
            log.warn("Erro ao obter ID do usuário logado: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage(), e);
        }
    }

    // Endpoint para obter os detalhes do UserEntity local do usuário autenticado
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<UserEntity> getCurrentUserDetails() {
        try {
            UserEntity currentUser = userService.findOrCreateUserFromToken();
            return ResponseEntity.ok(currentUser);
        } catch (IllegalStateException e) {
            log.warn("Erro ao obter detalhes do usuário logado: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage(), e);
        }
    }


    // Endpoints para administração de usuários (espelhos locais) - protegidos por ADMIN role
    @GetMapping("/findById")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserEntity> findUserByLocalId(@RequestParam Long id) {
        try {
            return ResponseEntity.ok(userService.findById(id));
        } catch (Exception e) { // UserNotFoundException será capturada aqui
            log.error("Erro ao buscar usuário por ID local {}: {}", id, e.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        }
    }

    @GetMapping("/findByUsername")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserEntity> findUserByUsername(@RequestParam String username) {
        try {
            // Este busca pelo username no banco local, que deve ser o espelho do Keycloak
            return ResponseEntity.ok(userService.findByUsernameLocal(username));
        } catch (Exception e) {
            log.error("Erro ao buscar usuário por username local {}: {}", username, e.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        }
    }

    @GetMapping("/findAll")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<UserEntity>> findAllUsers(Pageable pageable) {
        try {
            return ResponseEntity.ok(userService.findAll(pageable));
        } catch (Exception e) {
            log.error("Erro ao buscar todos os usuários: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro ao buscar usuários", e);
        }
    }

    @PostMapping("/admin/save-mirror")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserEntity> saveUserMirror(@RequestBody UserEntity user) {
        try {
            // Este UserEntity viria com keycloakId, username, role preenchidos
            // UserService.saveUserMirror faria a lógica de salvar/atualizar o espelho
            UserEntity savedUser = userService.saveUserMirror(user);
            return new ResponseEntity<>(savedUser, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            log.error("Erro de argumento ao salvar espelho de usuário: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (Exception e) {
            log.error("Erro inesperado ao salvar espelho de usuário: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro ao salvar espelho de usuário", e);
        }
    }

    // A atualização de usuários agora deve ser feita no Keycloak.
    // O espelho local pode ser atualizado via findOrCreateUserFromToken na próxima autenticação.

    @DeleteMapping("/admin/delete-local/{localId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> deleteUserLocal(@PathVariable Long localId) {
        try {
            String message = userService.deleteUserByLocalId(localId);
            return ResponseEntity.ok(Map.of("message", message));
        } catch (Exception e) { // Captura UserNotFoundException
            log.error("Erro ao deletar usuário local ID {}: {}", localId, e.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        }
    }

    // O endpoint /check-username pode ainda ser útil para verificar se um username (vindo do Keycloak)
    // já está espelhado no banco de dados local, mas seu propósito muda um pouco.
    @GetMapping("/check-username")
    @PreAuthorize("permitAll()") // Ou proteja se necessário
    public ResponseEntity<Map<String, Boolean>> checkUsernameAvailability(@RequestParam String username) {
        // Verifica se o username já existe no banco de dados LOCAL.
        // Isso não verifica no Keycloak.
        return ResponseEntity.ok(Map.of("isTakenLocally", userService.isUsernameTaken(username)));
    }
}