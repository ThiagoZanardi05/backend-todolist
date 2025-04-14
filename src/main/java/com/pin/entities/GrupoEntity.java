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
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class GrupoEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private String nome;

    @Column(nullable = false)
    private String descricao;

    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private UserEntity user;

    @OneToMany(mappedBy = "grupo", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private List<ItemEntity> itens;

    @ManyToOne
    @JoinColumn(name = "equipe_id")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private EquipeEntity equipe;
}
