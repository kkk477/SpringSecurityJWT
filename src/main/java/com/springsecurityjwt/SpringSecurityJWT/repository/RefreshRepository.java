package com.springsecurityjwt.SpringSecurityJWT.repository;

import com.springsecurityjwt.SpringSecurityJWT.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    Boolean existsByRefresh(String refresh);

    void deleteByRefresh(String refresh);
}
