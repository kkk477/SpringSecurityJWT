package com.springsecurityjwt.SpringSecurityJWT.service;

import com.springsecurityjwt.SpringSecurityJWT.Dto.CustomUserDetails;
import com.springsecurityjwt.SpringSecurityJWT.entity.UserEntity;
import com.springsecurityjwt.SpringSecurityJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // DB에서 조회
        UserEntity userEntity = userRepository.findUserEntityByUsername(username);

        if(userEntity != null) {

            // UserDetails에 담아서 return
            return new CustomUserDetails(userEntity);
        }

        return null;
    }
}
