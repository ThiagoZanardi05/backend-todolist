package com.pin.dto; // Crie um pacote dto

import java.util.List;
// Importe um DTO para Item também, se precisar mostrar itens
// import com.pin.dto.ItemSimpleDTO;

public class GrupoDTO {
    private Long id;
    private String nome;
    private String descricao;
    private String username; // Apenas o nome do usuário criador
    // private List<ItemSimpleDTO> itens; // Opcional: lista de DTOs de item

    // Getters e Setters (ou use Lombok @Data, @Getter, @Setter)

    // Exemplo de Getters/Setters manuais
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getNome() { return nome; }
    public void setNome(String nome) { this.nome = nome; }
    public String getDescricao() { return descricao; }
    public void setDescricao(String descricao) { this.descricao = descricao; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    // public List<ItemSimpleDTO> getItens() { return itens; }
    // public void setItens(List<ItemSimpleDTO> itens) { this.itens = itens; }
}

// Opcional: DTO simples para Item, se for incluir na resposta do Grupo
/*
package com.pin.dto;
public class ItemSimpleDTO {
    private Long id;
    private String nome;
    private boolean feita;
    // Getters/Setters
}
*/