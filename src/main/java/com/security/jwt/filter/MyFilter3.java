package com.security.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter { // javax.servlet의 Filter

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // ID와 PW가 정상적으로 들어와서 로그인이 완료되었을 때 토큰을 만들어주고 그걸 응답해주면 된다.
        // 요청할 때마다 header에 Authorization에 value 값으로 토큰을 가지고 오겠지?
        // 그 때 토큰이 넘어오면, 이 토큰이 내가 만든 토큰이 맞는지 검증만 하면 됨.(RSA, HS256)

        // 토큰을 만들었다고 가정을 하고 moon이라는 토큰이 넘어오면 인증이 되게 하고,
        // 토큰이 일치하지 않으면 필터를 못타게 해서 controller에 진입조차 못하도록 만들어보자.
        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");  // 리퀘스트의 헤더에서 Authorization을 String으로 받아온다.
            System.out.println("headerAuth = " + headerAuth);
            System.out.println("필터3");

            if (headerAuth.equals("moon")) {  // 토큰이 "moon"과 일치하면
                chain.doFilter(req, res);  // 필터 체인으로 통과
            } else {  // 토큰이 일치하지 않으면 필터 종료
                PrintWriter out = res.getWriter();
                out.println("인증 안됨!");
            }
        }
    }
}
