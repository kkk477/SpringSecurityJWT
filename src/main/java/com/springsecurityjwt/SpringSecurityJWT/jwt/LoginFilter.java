package com.springsecurityjwt.SpringSecurityJWT.jwt;

import com.springsecurityjwt.SpringSecurityJWT.Dto.CustomUserDetails;
import com.springsecurityjwt.SpringSecurityJWT.entity.RefreshEntity;
import com.springsecurityjwt.SpringSecurityJWT.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    // form login 이 켜져있으면 이 클래스 자동으로 사용되는데 jwt 쓸려고 껐으니까 이걸 다시 만들어줘야함.

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshRepository refreshRepository;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 스프링 시큐리티에서 username, password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token에 담은 정보 검증을 위해 AuthenticationManager로 전달
        return authenticationManager.authenticate(authenticationToken);
    }

    // 로그인 성공시 실행하는 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
//        String username = userDetails.getUsername();
//
//        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        String role = auth.getAuthority();
//
//        String token = jwtUtil.createJwt(username, role, 60*60*100L);
//        response.addHeader("Authorization", "Bearer " + token);
        /**-----------------------------Refresh token Version----------------------------------**/

        // 유저 정보
        String username = authResult.getName();

        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 60 * 10000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 60 * 60 * 24 * 1000L);

        //Refresh 토큰 저장
        addRefreshEntity(username, refresh, 60 * 60 * 24 * 1000L);

        // 응답 설정
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    // 로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }
}
