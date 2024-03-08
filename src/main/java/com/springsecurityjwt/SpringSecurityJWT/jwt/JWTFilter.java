package com.springsecurityjwt.SpringSecurityJWT.jwt;

import com.springsecurityjwt.SpringSecurityJWT.Dto.CustomUserDetails;
import com.springsecurityjwt.SpringSecurityJWT.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

//        // request에서 Authorization 헤더 찾음
//        String authorization = request.getHeader("Authorization");
//
//        // Authorization 헤더 검증
//        if((authorization == null) || (!authorization.startsWith("Bearer "))) {
//            filterChain.doFilter(request, response);
//
//            // 토큰이 없거나, Bearer로 시작하지 않으면 메소드 종료
//            return;
//        }
//
//        String token = authorization.split(" ")[1];
//
//        // 토큰 소멸 시간 검증
//        if(jwtUtil.isExpired(token)) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        // 토큰에서 username, role 가져옴
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        // UserEntity에 회원 정보 담기
//        UserEntity userEntity = new UserEntity();
//        userEntity.setUsername(username);
//
//        // password를 DB에서 가져올 수도 있지만, 그러면 모든 요청마다 DB에 접근해야함
//        userEntity.setPassword("temppassword");
//        userEntity.setRole(role);
//
//        // CustomUserDetails 만들어서 UsernamePasswordAuthenticationToken에 넣어서 Spring Security가 관리하게 인증토큰 생성
//        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        // 세션에 사용자 등록
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);

        // 헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        // 토큰이 없다면 다음 필터로 넘김
        if(accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        }catch (ExpiredJwtException e) {

            // response body
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 토큰이 access 인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if(!category.equals("access")) {

            // response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            // response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
