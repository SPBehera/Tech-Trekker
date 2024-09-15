package org.jt.tech_trekker.repository;

import java.util.Optional;

import org.jt.tech_trekker.model.WriterInfo;
import org.springframework.data.jpa.repository.JpaRepository;

public interface WriterInfoRepository extends JpaRepository<WriterInfo, Integer> {
    Optional<WriterInfo> findByEmail(String email);
    
}

