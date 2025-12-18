package ru.mtuci.coursemanagement.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class SecurityAuditLogger {

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        log.warn("SECURITY_AUDIT: Successful login for {}",
                event.getAuthentication().getName());
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        log.warn("SECURITY_AUDIT: Failed login attempt for {}: {}",
                event.getAuthentication().getName(),
                event.getException().getMessage());
    }

    @EventListener
    public void onLogoutSuccess(LogoutSuccessEvent event) {
        log.warn("SECURITY_AUDIT: User logged out: {}",
                event.getAuthentication().getName());
    }
}
