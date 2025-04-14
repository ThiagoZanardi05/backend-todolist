package com.pin.services;

import com.pin.dto.GrupoDTO; // Importar o DTO
import com.pin.entities.GrupoEntity;
import com.pin.repositories.GrupoRepository; // Supondo que você tenha um repositório
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Importar Transactional

import java.util.List;
import java.util.stream.Collectors;

@Service
public class GrupoService {

    @Autowired
    private GrupoRepository grupoRepository; // Injete seu repositório

    // Método original (pode manter se usado internamente)
    @Transactional(readOnly = true) // Garante sessão aberta para ler user.username
    public List<GrupoEntity> findAllEntities() {
        return grupoRepository.findAll(); // Ou seu método de busca
    }

    // NOVO MÉTODO para retornar DTOs para a API
    @Transactional(readOnly = true) // Necessário para acessar grupo.getUser().getUsername()
    public List<GrupoDTO> findAll() {
        List<GrupoEntity> entities = grupoRepository.findAll(); // Busca as entidades

        // Mapeia cada entidade para um DTO
        return entities.stream().map(this::mapEntityToDTO).collect(Collectors.toList());
    }

    // Método helper para mapear Entidade para DTO
    public GrupoDTO mapEntityToDTO(GrupoEntity entity) {
        if (entity == null) return null;
        GrupoDTO dto = new GrupoDTO();
        dto.setId(entity.getId());
        dto.setNome(entity.getNome());
        dto.setDescricao(entity.getDescricao());
        // Acessa o usuário DENTRO da transação
        if (entity.getUser() != null) {
            dto.setUsername(entity.getUser().getUsername());
        }
        // NÃO mapeie a lista de itens aqui para evitar o LazyInitializationException
        // Se precisar dos itens, carregue-os explicitamente (Opção 2) ou use outro DTO/endpoint
        return dto;
    }

    // Adapte os outros métodos (save, findById, update) para usarem ou retornarem DTOs também
    // Exemplo findById:
    @Transactional(readOnly = true)
    public GrupoDTO findDTOById(Long id) {
        return grupoRepository.findById(id)
                .map(this::mapEntityToDTO)
                .orElse(null); // Ou lance exceção Not Found
    }

    // ... outros métodos do serviço ...
    public GrupoEntity save(GrupoEntity grupo) { /* ... lógica de save ... */ return grupoRepository.save(grupo); }
    public GrupoEntity findById(Long id) { return grupoRepository.findById(id).orElse(null); }
    public GrupoEntity update(GrupoEntity grupo) { /* ... lógica de update ... */ return grupoRepository.save(grupo); }
    public String delete(Long id) { grupoRepository.deleteById(id); return "Grupo deletado"; }
}