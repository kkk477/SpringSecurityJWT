package com.springsecurityjwt.SpringSecurityJWT.repository;

import com.springsecurityjwt.SpringSecurityJWT.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Boolean existsUserEntityByUsername(String username);

    UserEntity findUserEntityByUsername(String username);
}
