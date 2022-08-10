package com.security.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter { // javax.servlet의 Filter

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터2");
        chain.doFilter(request, response);  // 필터를 통과할 때 프로세스가 끝나지 않도록 체인에 넘겨줘야 한다.
    }
}
