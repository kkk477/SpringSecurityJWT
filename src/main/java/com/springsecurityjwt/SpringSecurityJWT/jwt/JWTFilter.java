package com.springsecurityjwt.SpringSecurityJWT.jwt;

import com.springsecurityjwt.SpringSecurityJWT.Dto.CustomUserDetails;
import com.springsecurityjwt.SpringSecurityJWT.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request에서 Authorization 헤더 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if((authorization == null) || (!authorization.startsWith("Bearer "))) {
            filterChain.doFilter(request, response);

            // 토큰이 없거나, Bearer로 시작하지 않으면 메소드 종료
            return;
        }

        String token = authorization.split(" ")[1];

        // 토큰 소멸 시간 검증
        if(jwtUtil.isExpired(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰에서 username, role 가져옴
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // UserEntity에 회원 정보 담기
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);

        // password를 DB에서 가져올 수도 있지만, 그러면 모든 요청마다 DB에 접근해야함
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        // CustomUserDetails 만들어서 UsernamePasswordAuthenticationToken에 넣어서 Spring Security가 관리하게 인증토큰 생성
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
