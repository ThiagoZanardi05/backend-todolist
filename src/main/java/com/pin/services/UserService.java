package com.pin.services;

import com.pin.entities.UserEntity;
import com.pin.exception.UserNotFoundException;
// import com.pin.exception.UsernameAlreadyExistsException; // Pode não ser mais necessário se o username for apenas um espelho
import com.pin.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
// Não precisamos mais de PasswordEncoder aqui

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    // O PasswordEncoder foi removido pois as senhas são gerenciadas pelo Keycloak.

    /**
     * Busca um UserEntity local pelo ID do Keycloak (claim 'sub' do token).
     * Se não existir, cria um novo UserEntity local com base nas informações do token JWT.
     * Este método é crucial para vincular o usuário autenticado via Keycloak
     * a uma representação local para relacionamentos de banco de dados.
     */
    @Transactional
    public UserEntity findOrCreateUserFromToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            // Isso pode acontecer se o endpoint for público ou se houver um problema na configuração de segurança
            log.warn("Tentativa de obter usuário do token, mas nenhuma autenticação JWT válida encontrada.");
            throw new IllegalStateException("Nenhum usuário autenticado via JWT encontrado ou o principal não é um JWT.");
        }

        String keycloakId = jwt.getClaimAsString(JwtClaimNames.SUB);
        String username = jwt.getClaimAsString("preferred_username"); // Username do Keycloak
        List<String> rolesFromToken = jwt.getClaimAsStringList("realm_access.roles"); // Ajuste a claim se necessário

        if (keycloakId == null) {
            log.error("Claim 'sub' (Keycloak ID) não encontrada no token JWT. Token: {}", jwt.getClaims());
            throw new IllegalStateException("Claim 'sub' (Keycloak ID) não encontrada no token JWT.");
        }
        if (username == null) {
            // Usar keycloakId como username se preferred_username não estiver disponível.
            // Isso garante que o campo username, que é unique e not-null, tenha um valor.
            log.warn("Claim 'preferred_username' não encontrada no token JWT para keycloakId: {}. Usando keycloakId como username local.", keycloakId);
            username = keycloakId;
        }

        // Tenta encontrar o usuário pelo ID do Keycloak primeiro (mais confiável)
        Optional<UserEntity> userOpt = userRepository.findByKeycloakId(keycloakId);

        UserEntity userEntity;
        if (userOpt.isPresent()) {
            userEntity = userOpt.get();
            log.debug("Usuário encontrado no banco local pelo keycloakId: {}", keycloakId);
            // Opcional: Atualizar o username local se ele mudou no Keycloak
            if (!username.equals(userEntity.getUsername())) {
                log.info("Username para keycloakId {} mudou de '{}' para '{}'. Atualizando no banco local.", keycloakId, userEntity.getUsername(), username);
                // Antes de mudar o username, verifique se o novo username já não está em uso por OUTRO keycloakId.
                Optional<UserEntity> conflictingUser = userRepository.findByUsername(username);
                if (conflictingUser.isPresent() && !conflictingUser.get().getKeycloakId().equals(keycloakId)) {
                    log.warn("Tentativa de atualizar username para '{}' para keycloakId {}, mas este username já está em uso pelo keycloakId {}. Mantendo username antigo '{}'.",
                            username, keycloakId, conflictingUser.get().getKeycloakId(), userEntity.getUsername());
                    // Decide como lidar: manter o antigo, adicionar um sufixo, etc. Por enquanto, não atualiza se houver conflito.
                } else {
                    userEntity.setUsername(username);
                }
            }
        } else {
            log.info("Usuário com keycloakId {} não encontrado no banco local. Criando novo usuário local.", keycloakId);
            // Antes de criar, verifique se o username já existe (caso de migração ou username não único no Keycloak entre realms diferentes)
            Optional<UserEntity> existingByUsername = userRepository.findByUsername(username);
            if (existingByUsername.isPresent()) {
                // Username já existe. Isso pode ser um usuário antigo que precisa ser vinculado ao keycloakId,
                // ou um conflito genuíno se usernames não são globalmente únicos e você está reutilizando.
                log.warn("Tentando criar usuário com keycloakId {} e username '{}', mas o username já existe para o usuário local ID {}. Vinculando keycloakId ao usuário existente.",
                        keycloakId, username, existingByUsername.get().getId());
                userEntity = existingByUsername.get();
                userEntity.setKeycloakId(keycloakId); // Vincula
            } else {
                userEntity = new UserEntity();
                userEntity.setKeycloakId(keycloakId);
                userEntity.setUsername(username);
            }
        }

        // Sincroniza o role principal. Pode ser uma lógica mais elaborada.
        // Exemplo: pegar o primeiro role da lista ou o mais "importante".
        if (rolesFromToken != null && !rolesFromToken.isEmpty()) {
            String primaryRole = rolesFromToken.stream()
                    .map(String::toUpperCase)
                    .filter(r -> r.equals("ADMIN") || r.equals("USER")) // Filtra por roles conhecidos pela sua aplicação
                    .findFirst()
                    .orElse("USER"); // Role padrão se nenhum dos conhecidos for encontrado
            userEntity.setRole(primaryRole);
        } else {
            userEntity.setRole(userEntity.getRole() == null ? "USER" : userEntity.getRole()); // Mantém o role existente se nenhum vier ou define padrão
        }
        userEntity.setPassword(null); // Garante que a senha local não é usada/armazenada

        return userRepository.save(userEntity);
    }

    /**
     * Retorna o ID (do banco de dados local) do usuário autenticado.
     * Usa findOrCreateUserFromToken para garantir que o usuário local exista.
     */
    public Long getLoggedUserId() {
        UserEntity loggedUser = findOrCreateUserFromToken();
        if (loggedUser == null || loggedUser.getId() == null) {
            // Isso não deveria acontecer se findOrCreateUserFromToken funcionar corretamente
            log.error("Não foi possível obter o ID do usuário local para o usuário autenticado.");
            throw new IllegalStateException("Não foi possível determinar o ID do usuário local.");
        }
        return loggedUser.getId();
    }

    // Métodos CRUD para UserEntity (gerenciados localmente, mas identidade vem do Keycloak)
    // Estes métodos operam sobre o ID LOCAL do UserEntity.

    public UserEntity findById(Long localId) {
        return userRepository.findById(localId)
                .orElseThrow(() -> new UserNotFoundException("Usuário não encontrado com ID local: " + localId));
    }

    public UserEntity findByUsernameLocal(String username) {
        // Este método busca pelo username no seu banco local.
        // Útil se você precisa encontrar um UserEntity local pelo username que foi sincronizado do Keycloak.
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Usuário não encontrado com username local: " + username));
    }

    public UserEntity findByKeycloakId(String keycloakId) {
        return userRepository.findByKeycloakId(keycloakId)
                .orElseThrow(() -> new UserNotFoundException("Usuário não encontrado com Keycloak ID: " + keycloakId));
    }

    public Page<UserEntity> findAll(Pageable pageable) {
        return userRepository.findAll(pageable);
    }

    // O método de "save" público para UserController pode ser reavaliado.
    // Geralmente, os usuários locais são criados/atualizados via findOrCreateUserFromToken.
    // Se você precisar de um endpoint administrativo para criar um "espelho" local, ele seria diferente.
    @Transactional
    public UserEntity saveUserMirror(UserEntity user) { // Renomeado para clareza
        // Este método seria para um admin criar/atualizar o espelho local,
        // mas a fonte da verdade é o Keycloak.
        if (user.getKeycloakId() == null || user.getKeycloakId().trim().isEmpty()){
            throw new IllegalArgumentException("Keycloak ID é obrigatório para salvar um espelho de usuário.");
        }
        // Validações adicionais podem ser necessárias.
        // Garante que a senha não seja definida.
        user.setPassword(null);
        return userRepository.save(user);
    }


    // A deleção aqui deleta o registro LOCAL. Não deleta o usuário do Keycloak.
    @Transactional
    public String deleteUserByLocalId(Long localId) {
        if (!userRepository.existsById(localId)) {
            throw new UserNotFoundException("Tentativa de deletar usuário local inexistente com ID: " + localId);
        }
        userRepository.deleteById(localId);
        log.info("Usuário local com ID {} deletado.", localId);
        return "Usuário local deletado com ID: " + localId;
    }

    // Este método pode não ser mais relevante da mesma forma
    public boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
}