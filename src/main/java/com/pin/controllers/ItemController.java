package com.pin.controllers;

import com.pin.entities.ItemEntity;
import com.pin.services.ItemService;
import org.slf4j.Logger; // Import Logger
import org.slf4j.LoggerFactory; // Import LoggerFactory
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException; // For cleaner error responses

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/item")
public class ItemController {

    private static final Logger log = LoggerFactory.getLogger(ItemController.class); // Logger instance

    @Autowired
    private ItemService itemService;

    @GetMapping("/findAll")
    public ResponseEntity<List<ItemEntity>> findAll() { // Return List<ItemEntity> directly
        try {
            List<ItemEntity> items = itemService.findAll();
            return new ResponseEntity<>(items, HttpStatus.OK);
        } catch (Exception e) { // Catch broader exceptions if necessary, but RuntimeException is often enough
            log.error("Erro ao buscar todos os itens: {}", e.getMessage(), e);
            // Return structured error (consider a dedicated error response class)
            Map<String, String> errorResponse = Map.of(
                    "message", "Erro interno ao buscar todos os itens.",
                    "detail", e.getMessage() // Be cautious about exposing details in production
            );
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR); // Return null or empty list for body on error
            // OR throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno ao buscar itens", e);
        }
    }

    @PostMapping("/save")
    public ResponseEntity<ItemEntity> save(@RequestBody ItemEntity item) { // Return saved ItemEntity
        try {
            ItemEntity savedItem = itemService.save(item);
            return new ResponseEntity<>(savedItem, HttpStatus.CREATED); // Return the actual saved object
        } catch (RuntimeException e) {
            log.error("Erro ao salvar item: {}", e.getMessage(), e);
            // Throw ResponseStatusException for standard error handling
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Erro ao salvar item: " + e.getMessage(), e);
            // Or return ResponseEntity with error body:
            // Map<String, String> errorResponse = Map.of("message", "Erro ao salvar item.", "detail", e.getMessage());
            // return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/findById")
    public ResponseEntity<ItemEntity> findById(@RequestParam Long id) { // Return found ItemEntity
        try {
            ItemEntity item = itemService.findById(id);
            return new ResponseEntity<>(item, HttpStatus.OK); // Return the actual found object
        } catch (RuntimeException e) { // Specifically catch not found or other errors
            log.warn("Item não encontrado com id {}: {}", id, e.getMessage()); // Log as warning if "not found" is common
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e); // Use NOT_FOUND for "not found" errors
            // Or return ResponseEntity:
            // Map<String, String> errorResponse = Map.of("message", e.getMessage());
            // return new ResponseEntity<>(null, HttpStatus.NOT_FOUND); // Or BAD_REQUEST depending on error type
        }
    }

    // --- Keep findAll20 and findAllUnMarked as they return lists ---
    // --- but consider optimizing the service methods ---
    @GetMapping("/findAll20")
    public ResponseEntity<List<List<ItemEntity>>> findAll20(@RequestParam Long grupoId) { // Return type matches service
        try {
            List<List<ItemEntity>> itemsGrouped = itemService.findAll20(grupoId);
            return new ResponseEntity<>(itemsGrouped, HttpStatus.OK);
        } catch (RuntimeException e) {
            log.error("Erro ao buscar itens agrupados por 20 para grupo {}: {}", grupoId, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro ao buscar itens agrupados: " + e.getMessage(), e);
        }
    }

    @GetMapping("/findAllUnMarked")
    public ResponseEntity<List<ItemEntity>> findAllUnMarked(@RequestParam Long grupoId) { // Correct parameter name and return type
        try {
            List<ItemEntity> unMarkedItems = itemService.findAllUnMarked(grupoId); // Use grupoId as parameter name
            return new ResponseEntity<>(unMarkedItems, HttpStatus.OK);
        } catch (RuntimeException e) {
            log.error("Erro ao buscar itens não marcados para grupo {}: {}", grupoId, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro ao buscar itens não marcados: " + e.getMessage(), e);
        }
    }

    @PutMapping("/favorite")
    public ResponseEntity<ItemEntity> favorite(@RequestParam Long id) { // Return updated ItemEntity
        try {
            // Modify ItemService.favorite to return the updated ItemEntity
            ItemEntity updatedItem = itemService.favorite(id);
            return new ResponseEntity<>(updatedItem, HttpStatus.OK);
        } catch (RuntimeException e) {
            log.error("Erro ao favoritar item com id {}: {}", id, e.getMessage(), e);
            if (e.getMessage() != null && e.getMessage().startsWith("Item not found")) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Erro ao favoritar item: " + e.getMessage(), e);
        }
    }

    @PutMapping("/update")
    public ResponseEntity<ItemEntity> update(@RequestBody ItemEntity item) { // Return updated ItemEntity
        try {
            ItemEntity updatedItem = itemService.update(item);
            return new ResponseEntity<>(updatedItem, HttpStatus.OK); // Return the actual updated object
        } catch (RuntimeException e) {
            log.error("Erro ao atualizar item {}: {}", item.getId(), e.getMessage(), e);
            if (e.getMessage() != null && e.getMessage().contains("does not exist")) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
            }
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Erro ao atualizar item: " + e.getMessage(), e);
        }
    }


    @DeleteMapping("/delete")
    // Option 1: Return No Content on success
    // public ResponseEntity<Void> delete(@RequestParam Long id) {
    // Option 2: Return a success message object
    public ResponseEntity<Map<String, String>> delete(@RequestParam Long id) {
        try {
            String message = itemService.delete(id);
            // Option 1:
            // if (message.contains("not found")) {
            //     throw new ResponseStatusException(HttpStatus.NOT_FOUND, message);
            // }
            // return ResponseEntity.noContent().build(); // HTTP 204

            // Option 2:
            Map<String, String> response = Map.of("message", message);
            if (message.contains("not found")) {
                // Although not found, the delete operation is often idempotent,
                // so OK might still be acceptable, or use NOT_FOUND if preferred.
                return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
            }
            return new ResponseEntity<>(response, HttpStatus.OK); // HTTP 200 with message

        } catch (RuntimeException e) { // Catch unexpected errors during delete
            log.error("Erro inesperado ao deletar item com id {}: {}", id, e.getMessage(), e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Erro inesperado ao deletar item: " + e.getMessage(), e);
        }
    }


}