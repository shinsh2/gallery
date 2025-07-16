package kr.co.wikibook.gallery.common.config;

import java.io.IOException;

import org.springframework.security.web.csrf.CsrfToken;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CsrfTokenLoggerFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        Object object = request.getAttribute("_csrf");      //_csrf 요청 특성에서 토큰의 값을 얻고 콘솔에 출력함
        CsrfToken token = (CsrfToken) object;

        log.info("CSRF Token : {}", token.getToken());

        chain.doFilter(request, response);
    }
}