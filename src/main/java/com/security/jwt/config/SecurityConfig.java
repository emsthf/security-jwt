package com.security.jwt.config;

import com.security.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity  // 시큐리티 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    // DI를 위해 CorsFilter를 불러온다
    private final CorsFilter corsFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
        http.csrf().disable();
        return http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션을 사용하지 않겠다는 뜻
                .and()
                // @CrossOrigin => 인증X면 통과 불가능, 시큐리티 필터에 등록하면 인증이 없어도 통과 가능
                .addFilter(corsFilter)  // 모든 요청이 이 필터를 타고 들어간다. 이렇게 되면 내 서버는 CORS 정책에서 벗어날 수 있다.(CORS 요청이 와도 다 허용이 됨)
                .formLogin().disable()  // formLogin 사용X
                .httpBasic().disable()  // 기본적인 http 방식 사용X
                // 권한에 따라 접근 제한
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll().and().build();
    }
}
