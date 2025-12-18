package ru.mtuci.coursemanagement.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import ru.mtuci.coursemanagement.model.User;
import ru.mtuci.coursemanagement.service.UserService;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Controller
@RequiredArgsConstructor
public class AuthController {
    private final UserService users;
    private final PasswordEncoder passwordEncoder;

    private final Map<String, FailedLoginAttempt> failedAttempts = new ConcurrentHashMap<>();
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_MINUTES = 15;

    private static class FailedLoginAttempt {
        private int count;
        private LocalDateTime firstAttempt;
        private LocalDateTime lastAttempt;
        private LocalDateTime lockedUntil;

        public FailedLoginAttempt() {
            this.count = 1;
            this.firstAttempt = LocalDateTime.now();
            this.lastAttempt = LocalDateTime.now();
        }

        public void increment() {
            this.count++;
            this.lastAttempt = LocalDateTime.now();
            if (this.count >= MAX_FAILED_ATTEMPTS) {
                this.lockedUntil = LocalDateTime.now().plusMinutes(LOCK_TIME_MINUTES);
            }
        }

        public boolean isLocked() {
            if (lockedUntil == null) return false;
            return LocalDateTime.now().isBefore(lockedUntil);
        }

        public long getRemainingLockTime() {
            if (lockedUntil == null) return 0;
            return TimeUnit.SECONDS.convert(
                    java.time.Duration.between(LocalDateTime.now(), lockedUntil).getSeconds(),
                    TimeUnit.SECONDS
            );
        }

        public void reset() {
            this.count = 0;
            this.lockedUntil = null;
        }
    }

    @GetMapping("/login")
    public String loginPage(@RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "logout", required = false) String logout,
                            Model model) {
        if (error != null) {
            model.addAttribute("error", "Неверное имя пользователя или пароль");
        }
        if (logout != null) {
            model.addAttribute("message", "Вы успешно вышли из системы");
        }
        return "login";
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpServletRequest req,
                          Model model) {
        FailedLoginAttempt attempt = failedAttempts.get(username);
        if (attempt != null && attempt.isLocked()) {
            long remainingMinutes = attempt.getRemainingLockTime() / 60;
            model.addAttribute("error",
                    String.format("Аккаунт заблокирован из-за множества неудачных попыток. Попробуйте через %d минут.",
                            remainingMinutes > 0 ? remainingMinutes : 1));
            log.warn("Blocked login attempt for locked user: {}", username);
            return "login";
        }

        Optional<User> opt = users.findByUsername(username);
        if (opt.isEmpty()) {
            log.warn("Login attempt for non-existent user: {}", username);
            model.addAttribute("error", "Неверное имя пользователя или пароль");
            return "login";
        }

        User user = opt.get();

        if (passwordEncoder.matches(password, user.getPassword())) {
            failedAttempts.remove(username);

            HttpSession session = req.getSession(true);
            session.setAttribute("username", username);
            session.setAttribute("role", user.getRole());
            session.setAttribute("userId", user.getId());

            session.setMaxInactiveInterval(30 * 60);

            log.info("User {} successfully logged in from IP: {}",
                    username, req.getRemoteAddr());

            if ("TEACHER".equals(user.getRole())) {
                return "redirect:/courses";
            } else {
                return "redirect:/";
            }
        } else {
            if (attempt == null) {
                attempt = new FailedLoginAttempt();
                failedAttempts.put(username, attempt);
            } else {
                attempt.increment();
            }

            int remainingAttempts = MAX_FAILED_ATTEMPTS - attempt.count;
            if (remainingAttempts <= 0) {
                model.addAttribute("error",
                        String.format("Аккаунт заблокирован на %d минут из-за множества неудачных попыток.",
                                LOCK_TIME_MINUTES));
                log.warn("Account locked for user: {} after {} failed attempts",
                        username, MAX_FAILED_ATTEMPTS);
            } else {
                model.addAttribute("error",
                        String.format("Неверное имя пользователя или пароль. Осталось попыток: %d",
                                remainingAttempts));
                log.warn("Failed login attempt for user: {} (attempt {} of {})",
                        username, attempt.count, MAX_FAILED_ATTEMPTS);
            }

            return "login";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session != null) {
            String username = (String) session.getAttribute("username");
            session.invalidate();
            log.info("User {} logged out", username);
        }
        return "redirect:/login?logout";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam(required = false, defaultValue = "STUDENT") String role,
                           Model model) {

        if (users.findByUsername(username).isPresent()) {
            model.addAttribute("error", "Пользователь с таким именем уже существует");
            return "register";
        }

        if (password == null || password.length() < 6) {
            model.addAttribute("error", "Пароль должен содержать минимум 6 символов");
            return "register";
        }

        String encodedPassword = passwordEncoder.encode(password);

        User newUser = new User(null, username, encodedPassword, role);
        users.save(newUser);

        log.info("New user registered: {} with role: {}", username, role);
        model.addAttribute("message", "Регистрация успешна. Теперь вы можете войти.");

        return "redirect:/login";
    }

    @GetMapping("/profile")
    public String profilePage(HttpServletRequest req, Model model) {
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("username") == null) {
            return "redirect:/login";
        }

        String username = (String) session.getAttribute("username");
        Optional<User> userOpt = users.findByUsername(username);

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            model.addAttribute("username", user.getUsername());
            model.addAttribute("role", user.getRole());
        }

        return "profile";
    }
}