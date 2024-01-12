package com.springsecurityjwt.SpringSecurityJWT.service;

import com.springsecurityjwt.SpringSecurityJWT.Dto.JoinDto;
import com.springsecurityjwt.SpringSecurityJWT.entity.UserEntity;
import com.springsecurityjwt.SpringSecurityJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Boolean joinProcess(JoinDto joinDto) {

        if(userRepository.existsUserEntityByUsername(joinDto.getUsername())) {
            return false;
        }

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(joinDto.getUsername());
        userEntity.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        userEntity.setRole("ROLE_ADMIN");

        userRepository.save(userEntity);
        return true;
    }
}
