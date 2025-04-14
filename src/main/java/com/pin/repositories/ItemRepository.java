package com.pin.repositories;

import com.pin.entities.ItemEntity;
import org.springframework.data.jpa.repository.JpaRepository;
// Import Page and Pageable if using pagination
// import org.springframework.data.domain.Page;
// import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ItemRepository extends JpaRepository<ItemEntity, Long> {

    // For optimized findAllGroup
    List<ItemEntity> findByGrupoId(Long grupoId);

    // For optimized findAllUnMarked
    List<ItemEntity> findByGrupoIdAndFeitaIsFalse(Long grupoId);

    // Example for Pagination (if replacing findAll20 logic)
    // Page<ItemEntity> findByGrupoId(Long grupoId, Pageable pageable);

}