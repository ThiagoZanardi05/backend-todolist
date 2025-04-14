package com.pin.repositories;

import com.pin.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional; // Importar Optional

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);
}