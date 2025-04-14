package com.pin.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
@Table
@Entity(name = "eventos")
public class EventoEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false)
    private Date data;

    @Column(nullable = false)
    private String titulo;

    @Column(nullable = false)
    private String descricao;

    @Column(nullable = false)
    private String codHex;

    @Column(columnDefinition = "boolean default false")
    private boolean favorito;

    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonIgnoreProperties({"users", "grupos", "itens", "eventos", "equipes"})
    private UserEntity user;
}
