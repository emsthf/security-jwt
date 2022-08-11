    package com.security.jwt.config;

    import com.security.jwt.filter.MyFilter3;
    import com.security.jwt.jwt.JwtAuthenticationFilter;
    import lombok.RequiredArgsConstructor;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.web.SecurityFilterChain;
    import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

    @Configuration
    @EnableWebSecurity  // 시큐리티 활성화 -> 기본 스프링 필터 체인에 등록
    @RequiredArgsConstructor
    public class SecurityConfig {

        // DI를 위해 CorsConfig를 불러온다
        private final CorsConfig corsConfig ;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
            return http
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션을 사용하지 않겠다는 뜻
                    .and()
                    // @CrossOrigin => 인증X면 통과 불가능, 시큐리티 필터에 등록하면 인증이 없어도 통과 가능
                    .formLogin().disable()  // formLogin 사용X
                    .httpBasic().disable()  // 기본적인 http 방식 사용X
                    .apply(new MyCustomDsl()) // 커스텀 필터 등록
                    .and()
                    // 권한에 따라 접근 제한
                    .authorizeRequests(authorize -> authorize.antMatchers("/api/v1/user/**")
                            .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                            .antMatchers("/api/v1/manager/**")
                            .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                            .antMatchers("/api/v1/admin/**")
                            .access("hasRole('ROLE_ADMIN')")
                            .anyRequest().permitAll()
                    )
                    .build();

                    // 람다를 사용하지 않은 깔끔하지 못한 코드...
    //                .authorizeRequests()
    //                .antMatchers("/api/v1/user/**")
    //                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    //                .antMatchers("/api/v1/manager/**")
    //                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    //                .antMatchers("/api/v1/admin/**")
    //                .access("hasRole('ROLE_ADMIN')")
    //                .anyRequest().permitAll()
        }

        public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

            @Override
            public void configure(HttpSecurity builder) throws Exception {
                AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
                builder
                        .addFilter(corsConfig.corsFilter())  // 모든 요청이 이 필터를 타고 들어간다. 이렇게 되면 내 서버는 CORS 정책에서 벗어날 수 있다.(CORS 요청이 와도 다 허용이 됨)
                        .addFilter(new JwtAuthenticationFilter(authenticationManager));  // UsernamePasswordAuthenticationFilter를 상속한 이 필터에 꼭 필요한 파라미터 AuthenticationManager
            }
        }
    }
