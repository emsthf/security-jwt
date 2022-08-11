package com.security.jwt.config.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// login 요청해서 username, password를 전송하면(POST 방식) UsernamePasswordAuthenticationFilter가 동작함.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도 중");

        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 로그인 시도
            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 sesseion 영역에 저장됨. => 이제 출력이 됬다는 뜻은 로그인이 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());
            System.out.println("=======================================");
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
