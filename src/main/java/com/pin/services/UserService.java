package com.pin.services;

import com.pin.entities.UserEntity;
import com.pin.exception.UserNotFoundException;
import com.pin.exception.UsernameAlreadyExistsException;
import com.pin.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public UserEntity save(UserEntity user) {
        if (user.getPassword() == null || user.getPassword().length() < 8) {
            throw new IllegalArgumentException("A senha deve ter no mínimo 8 caracteres.");
        }

        if (user.getId() == null && userRepository.existsByUsername(user.getUsername())) {
            throw new UsernameAlreadyExistsException("Username '" + user.getUsername() + "' já está em uso.");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public UserEntity findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Usuário não encontrado com ID: " + id));
    }

    public UserEntity findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Usuário não encontrado com username: " + username));
    }

    @Transactional
    public UserEntity update(UserEntity user) {
        if (user.getId() == null || !userRepository.existsById(user.getId())) {
            throw new UserNotFoundException("Tentativa de atualizar usuário inexistente com ID: " + user.getId());
        }

        if (user.getPassword() == null || user.getPassword().length() < 8) {
            throw new IllegalArgumentException("A senha deve ter no mínimo 8 caracteres.");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Transactional
    public String delete(Long id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException("Tentativa de deletar usuário inexistente com ID: " + id);
        }

        userRepository.deleteById(id);
        return "Usuário deletado com ID: " + id;
    }

    public boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }

    public Page<UserEntity> findAll(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    public Long getLoggedUserId() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
        return user.getId();
    }
}
