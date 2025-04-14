package com.pin.services;

import com.pin.entities.GrupoEntity;
import com.pin.entities.ItemEntity;
import com.pin.entities.UserEntity; // <-- Importar UserEntity
import com.pin.repositories.GrupoRepository; // <-- Importar GrupoRepository
import com.pin.repositories.ItemRepository;
import com.pin.repositories.UserRepository; // <-- Importar UserRepository
import org.slf4j.Logger; // <-- Importar Logger
import org.slf4j.LoggerFactory; // <-- Importar LoggerFactory
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.PageRequest; // Necessário se usar findAll20 com paginação real
import org.springframework.data.domain.Pageable;   // Necessário se usar findAll20 com paginação real


import java.util.ArrayList;
import java.util.Date; // Importar Date
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
public class ItemService {

    private static final Logger log = LoggerFactory.getLogger(ItemService.class); // Logger para debug

    @Autowired
    private ItemRepository itemRepository;

    @Autowired // <<--- INJETAR REPOSITÓRIO DO GRUPO
    private GrupoRepository grupoRepository;

    @Autowired // <<--- INJETAR REPOSITÓRIO DO USUÁRIO
    private UserRepository userRepository;

    @Transactional(readOnly = true)
    public List<ItemEntity> findAll() {
        log.debug("Buscando todos os itens");
        return itemRepository.findAll();
    }

    @Transactional // Garante que tudo acontece em uma transação
    public ItemEntity save(ItemEntity item) {
        log.info("Iniciando processo de save para item com nome: {}", item.getNome());

        // 1. Validar e Associar Grupo (Assumindo que grupo é obrigatório)
        if (item.getGrupo() == null || item.getGrupo().getId() == null) {
            log.error("Tentativa de salvar item sem ID de grupo.");
            throw new IllegalArgumentException("Grupo é obrigatório para salvar o item.");
        }

        Long grupoId = item.getGrupo().getId();
        log.info("Buscando GrupoEntity para associação com ID: {}", grupoId);
        GrupoEntity managedGrupo = grupoRepository.findById(grupoId)
                .orElseThrow(() -> {
                    log.error("Grupo com ID {} não encontrado no banco durante o save!", grupoId);
                    // Este erro deve ser capturado pelo controller e retornar 400 ou 404
                    return new RuntimeException("Grupo associado não encontrado com ID: " + grupoId);
                });
        item.setGrupo(managedGrupo); // <<< Define a entidade GRUPO gerenciada pelo JPA
        log.info("GrupoEntity ID {} associado ao ItemEntity.", grupoId);

        // 2. Validar e Associar Usuário (Assumindo que usuário é obrigatório)
        if (item.getUser() == null || item.getUser().getId() == null) {
            // Se o usuário não vier do request, você PRECISA obter o usuário logado aqui
            // Exemplo (simplificado - implemente sua lógica de segurança):
            // UserEntity currentUser = userService.getCurrentAuthenticatedUser();
            // item.setUser(currentUser);
            // log.info("Usuário logado ID {} associado ao item.", currentUser.getId());

            // Se não houver usuário logado e for obrigatório:
            log.error("Tentativa de salvar item sem ID de usuário e sem usuário logado definido.");
            throw new IllegalArgumentException("Usuário é obrigatório para salvar o item.");
        } else {
            // Se o ID do usuário veio do request (como no teste do Postman)
            Long userId = item.getUser().getId();
            log.info("Buscando UserEntity para associação com ID: {}", userId);
            UserEntity managedUser = userRepository.findById(userId)
                    .orElseThrow(() -> {
                        log.error("Usuário com ID {} não encontrado no banco durante o save!", userId);
                        return new RuntimeException("Usuário associado não encontrado com ID: " + userId);
                    });
            item.setUser(managedUser); // <<< Define a entidade USUÁRIO gerenciada pelo JPA
            log.info("UserEntity ID {} associado ao ItemEntity.", userId);
        }


        // 3. Outras Validações/Lógicas (Ex: Data default)
        if (item.getData() == null) {
            item.setData(new Date()); // Usa java.util.Date
            log.info("Data do item definida para a data/hora atual.");
        }
        // Garante que descrição não seja nula se vier como null (embora @Column(nullable=false) deva pegar)
        if (item.getDescricao() == null) {
            log.warn("Descrição do item chegou como null, definindo para string vazia.");
            item.setDescricao(""); // Evita null se a coluna for NOT NULL
        }


        // 4. Log Final e Persistência
        log.info("Objeto ItemEntity COMPLETO E ASSOCIADO pronto para salvar: ID={}, Nome={}, Descricao={}, GrupoID={}, UserID={}",
                item.getId(), item.getNome(), item.getDescricao(), item.getGrupo().getId(), item.getUser().getId());
        try {
            ItemEntity savedItem = itemRepository.save(item);
            log.info("ItemEntity salvo com sucesso com novo ID: {}", savedItem.getId());
            return savedItem;
        } catch (Exception e) {
            log.error("Erro EXATO durante itemRepository.save: {}", e.getMessage(), e);
            // Re-lança a exceção para o controller tratar e retornar 400/500
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public ItemEntity findById(Long id) {
        log.debug("Buscando item por ID: {}", id);
        Optional<ItemEntity> itemOptional = itemRepository.findById(id);
        return itemOptional.orElseThrow(() -> {
            log.warn("Item não encontrado com ID: {}", id);
            return new RuntimeException("Item not found with id: " + id); // Ou exceção customizada
        });
    }

    @Transactional
    public ItemEntity favorite(Long id) {
        log.info("Alternando estado favorito para item ID: {}", id);
        ItemEntity item = findById(id); // Reutiliza findById que já lança exceção se não achar
        item.setFavorito(!item.isFavorito());
        ItemEntity updatedItem = itemRepository.save(item); // Salva a alteração
        log.info("Estado favorito do item ID {} atualizado para: {}", id, updatedItem.isFavorito());
        return updatedItem;
    }

    // Otimize os métodos findAllUnMarked e findAllGroup se ainda não o fez no ItemRepository
    @Transactional(readOnly = true)
    public List<ItemEntity> findAllUnMarked(Long grupoId) {
        log.debug("Buscando itens não marcados para grupo ID: {}", grupoId);
        // Assume que o método otimizado existe no repositório
        return itemRepository.findByGrupoIdAndFeitaIsFalse(grupoId);
    }

    @Transactional(readOnly = true)
    public List<ItemEntity> findAllGroup(Long grupoId) {
        log.debug("Buscando todos os itens para grupo ID: {}", grupoId);
        // Assume que o método otimizado existe no repositório
        return itemRepository.findByGrupoId(grupoId);
    }

    @Transactional(readOnly = true)
    public List<List<ItemEntity>> findAll20(Long grupoId) {
        log.debug("Buscando itens agrupados de 20 para grupo ID: {}", grupoId);
        // Usando a versão otimizada de findAllGroup
        List<ItemEntity> total = this.findAllGroup(grupoId);
        List<List<ItemEntity>> separados = new ArrayList<>();
        int batchSize = 20;
        for (int i = 0; i < total.size(); i += batchSize) {
            int fim = Math.min(i + batchSize, total.size());
            separados.add(new ArrayList<>(total.subList(i, fim)));
        }
        log.debug("Itens agrupados em {} listas.", separados.size());
        return separados;
    }

    @Transactional
    public ItemEntity update(ItemEntity item) {
        log.info("Iniciando processo de update para item ID: {}", item.getId());
        if (item.getId() == null) {
            throw new IllegalArgumentException("ID do item é obrigatório para atualização.");
        }

        // 1. Busca o item existente OBRIGATORIAMENTE para garantir que ele existe
        ItemEntity existingItem = itemRepository.findById(item.getId())
                .orElseThrow(() -> {
                    log.error("Item não encontrado para atualização com ID: {}", item.getId());
                    return new RuntimeException("Item not found with id: " + item.getId());
                });
        log.debug("Item existente encontrado para update: {}", existingItem);

        // 2. Atualiza os campos primitivos/simples
        existingItem.setNome(item.getNome());
        // Usa getDescricao() pois o @JsonProperty já deve ter mapeado "description" para "descricao"
        existingItem.setDescricao(item.getDescricao() != null ? item.getDescricao() : "");
        existingItem.setFeita(item.isFeita());
        existingItem.setFavorito(item.isFavorito());
        existingItem.setData(item.getData()); // Assume que a data pode ser atualizada

        // 3. Atualiza Associação de Grupo (se necessário)
        GrupoEntity grupoParaAssociar = null; // Começa como null
        if (item.getGrupo() != null && item.getGrupo().getId() != null) {
            Long novoGrupoId = item.getGrupo().getId();
            // Só busca no banco se o ID for diferente do atual ou se o atual for nulo
            if (existingItem.getGrupo() == null || !novoGrupoId.equals(existingItem.getGrupo().getId())) {
                log.info("Atualizando associação de Grupo para ID: {}", novoGrupoId);
                grupoParaAssociar = grupoRepository.findById(novoGrupoId)
                        .orElseThrow(() -> {
                            log.error("Grupo com ID {} não encontrado durante update!", novoGrupoId);
                            return new RuntimeException("Grupo para atualização não encontrado com ID: " + novoGrupoId);
                        });
            } else {
                grupoParaAssociar = existingItem.getGrupo(); // Mantém o grupo existente se o ID for o mesmo
            }
        }
        // Define o grupo encontrado (ou null se nenhum grupo veio no request)
        existingItem.setGrupo(grupoParaAssociar);
        if (grupoParaAssociar != null) {
            log.info("Grupo ID {} associado ao item durante update.", grupoParaAssociar.getId());
        } else {
            log.info("Grupo desassociado do item durante update.");
        }


        // 4. Atualiza Associação de Usuário (GERALMENTE NÃO É FEITO NO UPDATE DO ITEM)
        // Se precisar MUITO atualizar o usuário dono do item (cuidado!), use lógica similar à do grupo:
        // Verifique se item.getUser() e item.getUser().getId() não são nulos
        // Compare com existingItem.getUser().getId()
        // Se diferente, busque o novo usuário com userRepository.findById()
        // Faça existingItem.setUser(managedUser) ou existingItem.setUser(null)

        // 5. Log Final e Persistência
        log.info("Objeto ItemEntity PRONTO PARA salvar (update): {}", existingItem);
        try {
            ItemEntity updatedItem = itemRepository.save(existingItem); // save() faz update se ID existe
            log.info("ItemEntity atualizado com sucesso ID: {}", updatedItem.getId());
            return updatedItem;
        } catch (Exception e) {
            log.error("Erro EXATO durante itemRepository.save (update): {}", e.getMessage(), e);
            throw e;
        }
    }

    @Transactional
    public String delete(Long id) {
        log.info("Tentando deletar item com ID: {}", id);
        // Reutiliza findById para verificar existência antes
        ItemEntity item = findById(id); // Lança exceção se não existir
        itemRepository.deleteById(id);
        String message = "Item with id " + id + " deleted successfully.";
        log.info(message);
        return message;
        // O catch da exceção do findById pode ser tratado no Controller
    }
}