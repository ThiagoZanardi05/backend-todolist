package com.pin.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Table
@Entity(name = "equipes")
public class EquipeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private String nome;

    @Column(nullable = false)
    private String descricao;

    @OneToMany(mappedBy = "equipe")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private List<GrupoEntity> grupos;

    @ManyToMany
    @JoinTable(
            name = "equipe_user",
            joinColumns = @JoinColumn(name = "equipe_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private List<UserEntity> users;
}
