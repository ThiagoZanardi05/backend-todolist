package com.pin.repositories;

import com.pin.entities.GrupoEntity;
import com.pin.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GrupoRepository extends JpaRepository<GrupoEntity, Long> {
}
