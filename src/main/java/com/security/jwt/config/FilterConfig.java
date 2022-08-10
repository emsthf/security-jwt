package com.security.jwt.config;

import com.security.jwt.filter.MyFilter1;
import com.security.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration  // IoC로 등록
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");  // 모든 요청에서 다 필터를 추가해라.
        bean.setOrder(0);  // 번호가 낮은 필터가 가장 먼저 실행됨. 0번이니 제일 먼저 걸리는 필터가 됨
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");  // 모든 요청에서 다 필터를 추가해라.
        bean.setOrder(1);  // 번호가 낮은 필터가 가장 먼저 실행됨. 위 필터1보다 나중에 동작함
        return bean;
    }
}
