package com.pin.services;

import com.pin.entities.GrupoEntity;
import com.pin.entities.ItemEntity;
import com.pin.entities.UserEntity;
import com.pin.exception.UserNotFoundException;
import com.pin.repositories.GrupoRepository;
import com.pin.repositories.ItemRepository;
// Remova UserRepository daqui se não for usado diretamente, UserService lida com isso.
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class ItemService {

    private static final Logger log = LoggerFactory.getLogger(ItemService.class);

    @Autowired
    private ItemRepository itemRepository;

    @Autowired
    private GrupoRepository grupoRepository; // Para buscar GrupoEntity

    @Autowired
    private UserService userService; // Injete o UserService para obter o usuário logado

    @Transactional(readOnly = true)
    public List<ItemEntity> findAll() {
        log.debug("Buscando todos os itens");
        return itemRepository.findAll();
    }

    @Transactional
    public ItemEntity save(ItemEntity item) {
        log.info("Iniciando processo de save para item com nome: {}", item.getNome());

        // 1. Obter o UserEntity local correspondente ao usuário autenticado via Keycloak
        UserEntity currentUser = userService.findOrCreateUserFromToken(); // Usa o método atualizado
        item.setUser(currentUser);
        log.info("UserEntity local ID {} (username: {}) associado ao ItemEntity.", currentUser.getId(), currentUser.getUsername());

        // 2. Validar e Associar Grupo (se o grupo vier no request e for obrigatório)
        if (item.getGrupo() != null && item.getGrupo().getId() != null) {
            Long grupoId = item.getGrupo().getId();
            log.debug("Buscando GrupoEntity para associação com ID: {}", grupoId);
            GrupoEntity managedGrupo = grupoRepository.findById(grupoId)
                    .orElseThrow(() -> {
                        log.error("Grupo com ID {} não encontrado no banco durante o save do item!", grupoId);
                        return new IllegalArgumentException("Grupo associado não encontrado com ID: " + grupoId);
                    });
            item.setGrupo(managedGrupo);
            log.debug("GrupoEntity ID {} associado ao ItemEntity.", grupoId);
        } else if (item.getGrupo() != null) {
            // Se um objeto grupo foi passado mas sem ID, é um erro ou precisa de criação de grupo.
            // Para este exemplo, vamos considerar um erro se o ID do grupo não for fornecido.
            log.warn("Tentativa de salvar item com objeto GrupoEntity, mas sem ID de grupo. Verifique o payload.");
            throw new IllegalArgumentException("ID do Grupo é necessário se o objeto Grupo for fornecido.");
        } else {
            log.debug("Item salvo sem associação a um grupo específico (grupo não fornecido ou ID nulo).");
            item.setGrupo(null); // Garante que está nulo se não for associado.
        }


        // 3. Outras Validações/Lógicas (Ex: Data default)
        if (item.getData() == null) {
            item.setData(new Date());
            log.debug("Data do item definida para a data/hora atual.");
        }
        if (item.getDescricao() == null) {
            // A anotação @Column(nullable=false) na entidade deve tratar isso no nível do banco.
            // Se a coluna for nullável, você pode definir um valor padrão.
            log.debug("Descrição do item é null. Será persistido como null se a coluna permitir.");
        }

        log.debug("Objeto ItemEntity pronto para salvar: Nome={}, Descricao={}, GrupoID={}, UserID={}",
                item.getNome(), item.getDescricao(),
                (item.getGrupo() != null ? item.getGrupo().getId() : "N/A"),
                item.getUser().getId());
        try {
            ItemEntity savedItem = itemRepository.save(item);
            log.info("ItemEntity salvo com sucesso com novo ID: {}", savedItem.getId());
            return savedItem;
        } catch (Exception e) {
            log.error("Erro durante itemRepository.save: {}", e.getMessage(), e);
            // Re-lança a exceção para o controller tratar e retornar resposta HTTP apropriada
            throw new RuntimeException("Falha ao salvar o item no banco de dados.", e);
        }
    }

    @Transactional(readOnly = true)
    public ItemEntity findById(Long id) {
        log.debug("Buscando item por ID: {}", id);
        return itemRepository.findById(id)
                .orElseThrow(() -> {
                    log.warn("Item não encontrado com ID: {}", id);
                    return new UserNotFoundException("Item não encontrado com id: " + id); // UserNotFound é genérico, poderia ser ItemNotFoundException
                });
    }

    @Transactional
    public ItemEntity favorite(Long id) {
        log.info("Alternando estado favorito para item ID: {}", id);
        ItemEntity item = findById(id); // Reutiliza findById que já lança exceção se não achar
        item.setFavorito(!item.isFavorito());
        ItemEntity updatedItem = itemRepository.save(item);
        log.info("Estado favorito do item ID {} atualizado para: {}", id, updatedItem.isFavorito());
        return updatedItem;
    }

    @Transactional(readOnly = true)
    public List<ItemEntity> findAllUnMarked(Long grupoId) {
        log.debug("Buscando itens não marcados para grupo ID: {}", grupoId);
        return itemRepository.findByGrupoIdAndFeitaIsFalse(grupoId);
    }

    // findAllGroup foi renomeado para findByGrupoId no repositório
    @Transactional(readOnly = true)
    public List<ItemEntity> findItemsByGrupoId(Long grupoId) {
        log.debug("Buscando todos os itens para grupo ID: {}", grupoId);
        return itemRepository.findByGrupoId(grupoId);
    }


    @Transactional(readOnly = true)
    public List<List<ItemEntity>> findAll20(Long grupoId) {
        log.debug("Buscando itens agrupados de 20 para grupo ID: {}", grupoId);
        List<ItemEntity> total = this.findItemsByGrupoId(grupoId); // Usa o método corrigido
        List<List<ItemEntity>> separados = new java.util.ArrayList<>();
        int batchSize = 20;
        for (int i = 0; i < total.size(); i += batchSize) {
            int fim = Math.min(i + batchSize, total.size());
            separados.add(new java.util.ArrayList<>(total.subList(i, fim)));
        }
        log.debug("Itens agrupados em {} listas.", separados.size());
        return separados;
    }

    @Transactional
    public ItemEntity update(ItemEntity itemInput) { // Renomeado para itemInput para clareza
        log.info("Iniciando processo de update para item ID: {}", itemInput.getId());
        if (itemInput.getId() == null) {
            throw new IllegalArgumentException("ID do item é obrigatório para atualização.");
        }

        ItemEntity existingItem = itemRepository.findById(itemInput.getId())
                .orElseThrow(() -> {
                    log.error("Item não encontrado para atualização com ID: {}", itemInput.getId());
                    return new UserNotFoundException("Item não encontrado com id: " + itemInput.getId());
                });
        log.debug("Item existente encontrado para update: {}", existingItem.getNome());

        // Atualiza os campos
        existingItem.setNome(itemInput.getNome());
        existingItem.setDescricao(itemInput.getDescricao()); // Descrição pode ser null se a coluna permitir
        existingItem.setFeita(itemInput.isFeita());
        existingItem.setFavorito(itemInput.isFavorito());
        existingItem.setData(itemInput.getData());

        // Lógica para atualizar o grupo associado, se fornecido
        if (itemInput.getGrupo() != null && itemInput.getGrupo().getId() != null) {
            if (existingItem.getGrupo() == null || !itemInput.getGrupo().getId().equals(existingItem.getGrupo().getId())) {
                GrupoEntity newGrupo = grupoRepository.findById(itemInput.getGrupo().getId())
                        .orElseThrow(() -> new IllegalArgumentException("Novo grupo associado não encontrado com ID: " + itemInput.getGrupo().getId()));
                existingItem.setGrupo(newGrupo);
                log.debug("Grupo do item atualizado para ID: {}", newGrupo.getId());
            }
        } else if (itemInput.getGrupo() == null && existingItem.getGrupo() != null) {
            // Se o input do grupo é null, significa que queremos desassociar o grupo
            log.debug("Desassociando grupo do item ID: {}", existingItem.getId());
            existingItem.setGrupo(null);
        }
        // O usuário (dono) do item geralmente não muda em uma operação de update do item.
        // Se precisar mudar, adicione lógica similar à do grupo.

        try {
            ItemEntity updatedItem = itemRepository.save(existingItem);
            log.info("ItemEntity atualizado com sucesso ID: {}", updatedItem.getId());
            return updatedItem;
        } catch (Exception e) {
            log.error("Erro durante itemRepository.save (update): {}", e.getMessage(), e);
            throw new RuntimeException("Falha ao atualizar o item no banco de dados.",e);
        }
    }

    @Transactional
    public String delete(Long id) {
        log.info("Tentando deletar item com ID: {}", id);
        if (!itemRepository.existsById(id)) {
            log.warn("Tentativa de deletar item inexistente com ID: {}", id);
            throw new UserNotFoundException("Item não encontrado para deletar com ID: " + id);
        }
        itemRepository.deleteById(id);
        String message = "Item com id " + id + " deletado com sucesso.";
        log.info(message);
        return message;
    }
}