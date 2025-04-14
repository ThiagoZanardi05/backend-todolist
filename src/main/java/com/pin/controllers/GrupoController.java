package com.pin.controllers;

import com.pin.dto.GrupoDTO; // Importar o DTO criado
import com.pin.entities.GrupoEntity; // Pode precisar para o corpo do save/update ainda
import com.pin.services.GrupoService;
import org.slf4j.Logger; // Opcional, mas bom para logar erros
import org.slf4j.LoggerFactory; // Opcional
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException; // Exemplo de exceção mais específica

@RestController
@RequestMapping("/api/grupo")
public class GrupoController {

    private static final Logger log = LoggerFactory.getLogger(GrupoController.class); // Opcional

    @Autowired
    private GrupoService grupoService;

    /**
     * Cria um novo grupo.
     * Recebe os dados básicos do grupo no corpo da requisição.
     * Retorna o DTO do grupo criado.
     */
    @PostMapping("/save")
    public ResponseEntity<?> save(@RequestBody GrupoDTO grupoDto) { // Recebe DTO ou entidade? Depende do frontend/serviço
        try {
            // Idealmente, o serviço save receberia um DTO ou dados específicos
            // e retornaria a Entidade salva ou o DTO salvo.
            // Vamos assumir que save ainda trabalha com Entidade por enquanto,
            // mas retorna a entidade salva para mapearmos para DTO.

            // Mapear DTO para Entidade (simplificado, pode precisar de um mapper)
            GrupoEntity grupoToSave = new GrupoEntity();
            grupoToSave.setNome(grupoDto.getNome());
            grupoToSave.setDescricao(grupoDto.getDescricao());
            // O User ID geralmente é pego do usuário autenticado no Service

            GrupoEntity savedEntity = grupoService.save(grupoToSave);

            // Mapear a entidade salva de volta para DTO para retornar na resposta
            GrupoDTO savedDto = grupoService.mapEntityToDTO(savedEntity); // Reutiliza o mapper do serviço

            log.info("Grupo salvo com sucesso: ID {}", savedEntity.getId());
            return new ResponseEntity<>(savedDto, HttpStatus.CREATED);

        } catch (Exception e) { // Ser mais específico se possível
            log.error("Erro ao salvar grupo: {}", e.getMessage(), e);
            Map<String, String> errorResponse = Map.of("message", "Erro ao salvar grupo: " + e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST); // Ou INTERNAL_SERVER_ERROR
        }
    }

    /**
     * Busca um grupo pelo ID e retorna seu DTO.
     */
    @GetMapping("/findById")
    public ResponseEntity<?> findById(@RequestParam Long id) {
        try {
            // Chama o método do serviço que já retorna o DTO
            GrupoDTO grupoDto = grupoService.findDTOById(id);

            if (grupoDto != null) {
                log.debug("Grupo encontrado por ID {}: {}", id, grupoDto.getNome());
                return new ResponseEntity<>(grupoDto, HttpStatus.OK);
            } else {
                log.warn("Grupo não encontrado com ID: {}", id);
                return new ResponseEntity<>(Map.of("message", "Grupo não encontrado com ID: " + id), HttpStatus.NOT_FOUND);
            }
        } catch (Exception e) { // Captura erros gerais do serviço
            log.error("Erro ao buscar grupo por ID {}: {}", id, e.getMessage(), e);
            Map<String, String> errorResponse = Map.of("message", "Erro ao buscar grupo por ID: " + e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Busca todos os grupos e retorna uma lista de DTOs.
     */
    @GetMapping("/findAll")
    public ResponseEntity<?> findAll() {
        try {
            // Chama o método do serviço que retorna a lista de DTOs
            List<GrupoDTO> grupos = grupoService.findAll();
            log.info("Buscando todos os grupos. Encontrados: {}", grupos.size());
            return new ResponseEntity<>(grupos, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Erro ao buscar todos os grupos: {}", e.getMessage(), e);
            Map<String, String> errorResponse = Map.of("message", "Erro ao buscar todos os grupos: " + e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Atualiza um grupo existente.
     * Recebe os dados do grupo a ser atualizado (provavelmente DTO).
     * Retorna o DTO do grupo atualizado.
     */
    @PutMapping("/update")
    public ResponseEntity<?> update(@RequestBody GrupoDTO grupoDto) { // Recebe DTO
        // Validar se o ID está presente no DTO
        if (grupoDto.getId() == null) {
            return new ResponseEntity<>(Map.of("message", "ID do grupo é obrigatório para atualização."), HttpStatus.BAD_REQUEST);
        }
        try {
            // Mapear DTO para Entidade para enviar ao serviço (ou serviço aceita DTO)
            GrupoEntity grupoToUpdate = new GrupoEntity();
            grupoToUpdate.setId(grupoDto.getId());
            grupoToUpdate.setNome(grupoDto.getNome());
            grupoToUpdate.setDescricao(grupoDto.getDescricao());
            // O serviço de update deve buscar a entidade existente e atualizar os campos

            GrupoEntity updatedEntity = grupoService.update(grupoToUpdate); // Serviço pode retornar entidade

            // Mapear entidade atualizada para DTO
            GrupoDTO updatedDto = grupoService.mapEntityToDTO(updatedEntity);

            log.info("Grupo atualizado com sucesso: ID {}", updatedEntity.getId());
            return new ResponseEntity<>(updatedDto, HttpStatus.OK);

        } catch (NoSuchElementException e) { // Exemplo: Se o update lançar isso se não encontrar
            log.warn("Tentativa de atualizar grupo não encontrado: ID {}", grupoDto.getId());
            return new ResponseEntity<>(Map.of("message", "Grupo não encontrado para atualização com ID: " + grupoDto.getId()), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            log.error("Erro ao atualizar grupo ID {}: {}", grupoDto.getId(), e.getMessage(), e);
            Map<String, String> errorResponse = Map.of("message", "Erro ao atualizar grupo: " + e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST); // Ou INTERNAL_SERVER_ERROR
        }
    }

    /**
     * Deleta um grupo pelo ID.
     * Retorna uma mensagem de sucesso.
     */
    @DeleteMapping("/delete")
    public ResponseEntity<?> delete(@RequestParam Long id) {
        try {
            // Serviço de delete pode lançar exceção se não encontrar
            String message = grupoService.delete(id);
            log.info("Grupo deletado com sucesso: ID {}", id);
            return new ResponseEntity<>(Map.of("message", message), HttpStatus.OK); // Retorna JSON com mensagem

        } catch (NoSuchElementException e) { // Exemplo
            log.warn("Tentativa de deletar grupo não encontrado: ID {}", id);
            return new ResponseEntity<>(Map.of("message", "Grupo não encontrado para deletar com ID: " + id), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            log.error("Erro ao deletar grupo ID {}: {}", id, e.getMessage(), e);
            Map<String, String> errorResponse = Map.of("message", "Erro ao deletar grupo: " + e.getMessage());
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR); // Ou BAD_REQUEST dependendo do erro
        }
    }
}