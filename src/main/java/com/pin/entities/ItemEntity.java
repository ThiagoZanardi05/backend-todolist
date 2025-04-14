package com.pin.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty; // <-- IMPORTAR
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "itens")
@Entity
public class ItemEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String nome;

    @Column(nullable = false) // Mantém a restrição do banco explícita
    @JsonProperty("description") // <-- ADICIONAR ESTA ANOTAÇÃO
    private String descricao; // Nome do campo Java permanece em português

    @Column
    private Date data;

    @Column(columnDefinition = "boolean default false")
    private boolean favorito;

    @Column(columnDefinition = "boolean default false")
    private boolean feita;

    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "users"})
    private UserEntity user;

    @ManyToOne
    @JoinColumn(name = "grupo_id")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "users"})
    private GrupoEntity grupo;
}