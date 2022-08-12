package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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

            // 토큰을 통해 로그인 시도
            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후, 정상이면 authentication이 리턴됨.
            // authentication이 리턴이 된다는 말은 DB에 있는 username과 password가 일치한다는 뜻.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨: " + principalDetails.getUser().getUsername());
            System.out.println("=======================================");
            // authentication 객체가 sesseion 영역에 저장을 해야하는데, 그 방법이 메서드에서 return하는 것.
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 하지만 단지 편리한 권한 처리때문에 session에 넣어주는 것.
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨: 인증이 완료되었다는 뜻!");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        // principalDetails 정보를 통해 JWT 토큰을 만들 것.

        // java-jwt 라이브러리를 사용해서 토큰 생성
        // 아래 방식은 RSA 방식이 아닌 사용 빈도가 더 높은 Hash 암호방식. HMAC256 방식의 특징이 서버만 알고 있는 SECRET 키 이다.
        String jwtToken = JWT.create()
                .withSubject("jwt study 토큰")  // 토큰의 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))  // 토큰의 만료 시간. 10분으로 설정
                .withClaim("id", principalDetails.getUser().getId())  // 비공개 클레임. 내가 넣고 싶은 값을 넣으면 됨.
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC256("Bianchi"));  // SECRET은 내 서버만 아는 고유한 값.

        // 클라이언트에 응답할 response 헤더에 키 값으로 Authorization, 벨류 값으로 "Bearer " + jwtToken을 담아서 보낸다.
        // 여기서 "Bearer "를 쓸때 꼭 주의할 점이 Bearer 뒤에 한 칸 공백을 넣어주는 것이다.
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
