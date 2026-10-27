package com.hospital.auth.controller;

import com.hospital.auth.controller.AuthController.BadCredentialsException;
import com.hospital.auth.dto.LoginRequest;
import com.hospital.auth.dto.LoginResponse;
import com.hospital.auth.dto.UserRegisterRequest;
import com.hospital.auth.model.UserAccount;
import com.hospital.auth.repository.UserAccountRepository;
import com.hospital.auth.util.JwtTokenProvider;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserAccountRepository users;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwt;

    public AuthController(UserAccountRepository users, PasswordEncoder encoder, JwtTokenProvider jwt) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody UserRegisterRequest req) {
        if (users.existsByUsername(req.getUsername()) || users.existsByEmail(req.getEmail())) {
            throw new IllegalArgumentException("Username or email already in use");
        }
        UserAccount u = new UserAccount();
        u.setUsername(req.getUsername());
        u.setEmail(req.getEmail());
        u.setPasswordHash(encoder.encode(req.getPassword()));
        u.setRole(req.getRole() == null ? "PATIENT" : req.getRole());
        users.save(u);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "User registered"));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req) {
        UserAccount u = users.findByUsername(req.getUsername())
                .filter(UserAccount::isEnabled)
                .filter(x -> encoder.matches(req.getPassword(), x.getPasswordHash()))
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));
        String token = jwt.generateToken(u.getUsername(), u.getRole());
        return new LoginResponse(token, "Bearer", jwt.getExpirationMs(), u.getUsername(), u.getRole());
    }

    /** Thrown for failed logins; mapped to 401 by GlobalExceptionHandler. */
    public static class BadCredentialsException extends RuntimeException {
        public BadCredentialsException(String m) { super(m); }
    }
}
