package com.pin.services;

import com.pin.entities.EquipeEntity;
import com.pin.repositories.EquipeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class EquipeService {

    @Autowired
    private EquipeRepository equipeRepository;

    public EquipeEntity save(EquipeEntity equipe) {
        return equipeRepository.save(equipe);
    }

    public EquipeEntity findById(Long id) {
        return equipeRepository.findById(id).orElseThrow(() -> new RuntimeException("Equipe not found"));
    }

    public List<List<EquipeEntity>> findAll() {
        List<EquipeEntity> total = equipeRepository.findAll();
        List<List<EquipeEntity>> separados = new ArrayList<>();

        for (int i = 0; i < total.size(); i += 20) {
            List<EquipeEntity> subLista = total.subList(i, Math.min(i + 20, total.size()));
            separados.add(new ArrayList<>(subLista));
        }

        return separados;
    }


    public EquipeEntity update(EquipeEntity equipe) {
        return equipeRepository.save(equipe);
    }

    public String delete(Long id) {
        equipeRepository.deleteById(id);
        return "Equipe deleted";
    }
}
