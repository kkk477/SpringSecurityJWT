package com.springsecurityjwt.SpringSecurityJWT.controller;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
public class MainController {

    @GetMapping("/")
    public String index() {

        // 컨트롤러의 경로에 대한 요청이 들어올 때마다 JWT Filter 를 거치기 때문에
        // SecurityContextHolder.getContext().setAuthentication(authToken);
        // 코드 때문에 컨트롤러에서 유저 정보를 가져올 수 있음
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        Collection<? extends GrantedAuthority> authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority authority = iterator.next();
        String role = authority.getAuthority();

        return "Main Controller" + username + role;
    }
}
