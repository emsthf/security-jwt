package com.security.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.security.jwt.config.auth.PrincipalDetails;
import com.security.jwt.model.User;
import com.security.jwt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter를 가지고 있는데, 그 필터 중에 BasicAuthenticationFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 됨.
    // 여기서 헤더 값을 확인해보면 되겠지?
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 들어옴.");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("jwtHeader = " + jwtHeader);

        // header에 jwt 토큰이 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {  // 토큰이 null이거나, Bearer로 시작하지 않으면
            chain.doFilter(request, response);  // 다시 필터를 타도록 넘겨버리고 리턴(다음 코드가 진행이 안되도록).
            return;
        }

        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");  // jwt 앞의 "Bearer " 부분 ""으로 치환
        // 암호화에 썼던 알고리즘으로 secret 키를 넣어 복호화를 하고, verify()로 서명. 서명이 정상적으로 되면 username을 가져와서 String으로 캐스팅해준다.
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됬을 때
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            System.out.println("userEntity.getUsername() = " + userEntity.getUsername());

            // userEntity값이 select 되면 정상적인 사용자라는 뜻.
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Authentication 객체를 만들건데 기존에 JwtAuthenticationFilter에서 만들었던 방법은 로그인을 진행을 해버리면서 만들었지만, 여기서는 Authentication 객체를 강제로 만들어 줄 것이다.
            // UsernamePasswordAuthenticationToken의 두번째 인자 password에 null을 넣는 이유는 PrincipalDetailsService를 통해서 로그인을 진행할 것이 아니라 가짜로 Authentication 객체를 만들 것이기 때문.
            // 이 Authentication 객체를 강제로 만드는 근거는 무었이냐? username이 인증이 된 상태(!=null)이기 때문.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());  // principalDetails.getAuthorities()로 유저의 권한을 읽어온다.

            // 강제로 시큐리티의 세션 공간에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);  // 다시 필터를 타도록 한다.
        }
    }
}