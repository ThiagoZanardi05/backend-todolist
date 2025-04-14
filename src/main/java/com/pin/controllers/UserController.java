package com.pin.controllers;

import com.pin.entities.UserEntity;
import com.pin.exception.UserNotFoundException;
import com.pin.exception.UsernameAlreadyExistsException;
import com.pin.services.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = "http://localhost:4200")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/save")
    public ResponseEntity<Object> save(@RequestBody UserEntity user) {
        try {
            return new ResponseEntity<>(userService.save(user), HttpStatus.CREATED);
        } catch (UsernameAlreadyExistsException e) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(createErrorResponse(e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao salvar usuário."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("Erro inesperado ao salvar usuário: " + e.getMessage()));
        }
    }

    @GetMapping("/findById")
    public ResponseEntity<Object> findById(@RequestParam Long id) {
        try {
            return ResponseEntity.ok(userService.findById(id));
        } catch (UserNotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND)
                    .body(createErrorResponse(e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao buscar usuário por ID."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("Erro inesperado ao buscar usuário por ID: " + e.getMessage()));
        }
    }

    @GetMapping("/findByUsername")
    public ResponseEntity<Object> findByUsername(@RequestParam String username) {
        try {
            return ResponseEntity.ok(userService.findByUsername(username));
        } catch (UserNotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND) // 404
                    .body(createErrorResponse(e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao buscar usuário por username."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("Erro inesperado ao buscar usuário por username: " + e.getMessage()));
        }
    }

    @GetMapping("/findAll")
    public ResponseEntity<Object> findAll(Pageable pageable) {
        try {
            return ResponseEntity.ok(userService.findAll(pageable));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao buscar lista de usuários."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR) // Erro genérico aqui pode ser 500
                    .body(createErrorResponse("Erro inesperado ao buscar lista de usuários: " + e.getMessage()));
        }
    }

    @PutMapping("/update")
    public ResponseEntity<Object> update(@RequestParam Long id, @RequestBody UserEntity user) {
        try {
            user.setId(id);
            UserEntity updatedUser = userService.update(user);
            return ResponseEntity.ok(updatedUser);
        } catch (UserNotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND) // 404
                    .body(createErrorResponse(e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao atualizar usuário."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("Erro inesperado ao atualizar usuário: " + e.getMessage()));
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Object> delete(@RequestParam Long id) {
        try {
            return ResponseEntity.ok(createSuccessResponse(userService.delete(id)));
        } catch (UserNotFoundException e) {
            return ResponseEntity
                    .status(HttpStatus.NOT_FOUND) // 404
                    .body(createErrorResponse(e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao deletar usuário."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse("Erro inesperado ao deletar usuário: " + e.getMessage()));
        }
    }

    @GetMapping("/check-username")
    public ResponseEntity<Object> checkUsernameAvailability(@RequestParam String username) {
        try {
            return ResponseEntity.ok(Map.of("isTaken", userService.isUsernameTaken(username)));
        } catch (DataAccessException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("Erro de banco de dados ao verificar username."));
        } catch (RuntimeException e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR) // Erro genérico aqui pode ser 500
                    .body(createErrorResponse("Erro inesperado ao verificar username: " + e.getMessage()));
        }
    }

    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("message", message);
        return errorResponse;
    }

    private Map<String, String> createSuccessResponse(String message) {
        Map<String, String> successResponse = new HashMap<>();
        successResponse.put("message", message);
        return successResponse;
    }
}