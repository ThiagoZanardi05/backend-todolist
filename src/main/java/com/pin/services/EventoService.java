package com.pin.services;

import com.pin.entities.EventoEntity;
import com.pin.repositories.EventoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class EventoService {

    @Autowired
    private EventoRepository eventoRepository;

    public EventoEntity save(EventoEntity evento) {
        return eventoRepository.save(evento);
    }

    public EventoEntity findById(Long id) {
        return eventoRepository.findById(id).orElseThrow(() -> new RuntimeException("Evento not found"));
    }

    public List<List<EventoEntity>> findAll() {
        List<EventoEntity> total = eventoRepository.findAll();
        List<List<EventoEntity>> separados = new ArrayList<>();

        for (int i = 0; i < total.size(); i += 20) {
            List<EventoEntity> subLista = total.subList(i, Math.min(i + 20, total.size()));
            separados.add(new ArrayList<>(subLista));
        }

        return separados;
    }


    public EventoEntity update(EventoEntity evento) {
        return eventoRepository.save(evento);
    }

    public String delete(Long id) {
        eventoRepository.deleteById(id);
        return "Evento deleted";
    }
}
