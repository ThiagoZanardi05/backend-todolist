package com.pin.controllers;

import com.pin.entities.EventoEntity;
import com.pin.services.EventoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/evento")
public class EventoController {

    @Autowired
    private EventoService eventoService;

    @PostMapping("/save")
    public ResponseEntity<String> save(@RequestBody EventoEntity evento) {
        try {
            return new ResponseEntity<>(String.valueOf(eventoService.save(evento)), HttpStatus.CREATED);

        } catch (RuntimeException e) {
            return new ResponseEntity<>(String.valueOf(e), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/findById")
    public ResponseEntity<String> findById(@RequestParam Long id) {
        try {
            return new ResponseEntity<>(String.valueOf(eventoService.findById(id)), HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(String.valueOf(e), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/findAll")
    public ResponseEntity<String> findAll() {
        try {
            return new ResponseEntity<>(String.valueOf(eventoService.findAll()), HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(String.valueOf(e), HttpStatus.BAD_REQUEST);
        }
    }

    @PutMapping("/update")
    public ResponseEntity<String> update(@RequestBody EventoEntity evento) {
        try {
            return new ResponseEntity<>(String.valueOf(eventoService.update(evento)), HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(String.valueOf(e), HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<String> delete(@RequestParam Long id) {
        try {
            return new ResponseEntity<>(String.valueOf(eventoService.delete(id)), HttpStatus.OK);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(String.valueOf(e), HttpStatus.BAD_REQUEST);
        }
    }
}