package ru.mtuci.coursemanagement.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(1)
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setHeader("Content-Security-Policy",
                "default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self'; " +
                        "img-src 'self'; " +
                        "font-src 'self'; " +
                        "connect-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "form-action 'self'; " +
                        "base-uri 'self'");

        httpResponse.setHeader("X-Frame-Options", "DENY");
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
        httpResponse.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        httpResponse.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
        httpResponse.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        httpResponse.setHeader("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=()");

        chain.doFilter(request, response);
    }
}