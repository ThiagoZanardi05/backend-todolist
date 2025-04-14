package com.pin.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
@Entity
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Username não pode ser vazio ou nulo.")
    @Size(min = 3, max = 50, message = "Username deve ter entre 3 e 50 caracteres.")
    @Column(nullable = false, unique = true)
    private String username;

    @NotBlank(message = "Password não pode ser vazio ou nulo.")
    @Size(min = 8, message = "Password deve ter no mínimo 8 caracteres.")
    @Column(nullable = false)
    private String password;

    @NotBlank(message = "Role não pode ser vazio ou nulo.")
    @Column(nullable = false)
    private String role;

    @NotNull
    @Min(value = 0, message = "Tentativas não pode ser menor que 0.")
    @Max(value = 3, message = "Tentativas não pode ser maior que 3.")
    @Column(nullable = false, columnDefinition = "int default 0")
    private int tentativas;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonIgnoreProperties({"user", "itens"})
    private List<GrupoEntity> grupos;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonIgnoreProperties({"user", "grupo"})
    private List<ItemEntity> itens;

    @ManyToMany(mappedBy = "user", fetch = FetchType.EAGER)
    @JsonIgnoreProperties({"users"})
    private List<EventoEntity> eventos;
}
