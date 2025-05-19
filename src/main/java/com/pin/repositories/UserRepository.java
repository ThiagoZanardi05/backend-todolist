package com.pin.repositories;

import com.pin.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);

    // NOVO MÉTODO para buscar pelo ID do Keycloak
    Optional<UserEntity> findByKeycloakId(String keycloakId);
}