package com.pin.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users") // Boa prática definir o nome da tabela explicitamente
@Entity
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // ID interno do seu banco

    @NotBlank(message = "Username não pode ser vazio ou nulo.")
    @Size(min = 1, max = 255, message = "Username deve ter entre 1 e 255 caracteres.") // Ajuste os tamanhos conforme necessário
    @Column(nullable = false, unique = true)
    public String username; // Este será o username do Keycloak (ex: preferred_username)

    // Campo de senha não é mais usado para autenticação.
    // Pode ser removido ou mantido como nullável se houver dados antigos.
    @Column(nullable = true)
    private String password;

    // Este 'role' pode ser usado para armazenar um role principal da aplicação,
    // sincronizado a partir dos roles do Keycloak.
    @Column(nullable = true) // Pode ser null se os roles forem sempre lidos do token em tempo real
    private String role;

    // O campo 'tentativas' provavelmente não é mais necessário, pois o Keycloak gerencia isso.
    // @NotNull
    // @Min(value = 0, message = "Tentativas não pode ser menor que 0.")
    // @Max(value = 3, message = "Tentativas não pode ser maior que 3.")
    // @Column(nullable = false, columnDefinition = "int default 0")
    // private int tentativas;

    // Adicionado para armazenar o ID do usuário do Keycloak (claim 'sub' do JWT)
    // Este é o link mais confiável para o usuário no Keycloak.
    @Column(unique = true, nullable = true, name = "keycloak_id") // Pode torná-lo nullable=false após migração/sincronização inicial
    private String keycloakId;

    // Relacionamentos (Usar FetchType.LAZY por padrão para coleções)
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonIgnoreProperties(value = {"user", "itens"}, allowSetters = true) // allowSetters=true pode ajudar com desserialização
    private List<GrupoEntity> grupos;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonIgnoreProperties(value = {"user", "grupo"}, allowSetters = true)
    private List<ItemEntity> itens;

    @ManyToMany(mappedBy = "user", fetch = FetchType.LAZY) // 'user' deve ser o nome do campo na EventoEntity que mapeia para UserEntity
    @JsonIgnoreProperties(value = {"users", "eventos"}, allowSetters = true) // Ajuste 'users' ou 'eventos' se necessário
    private List<EventoEntity> eventos; // Verifique o mappedBy na entidade EventoEntity
}