package com.example.jwt.domain.member.service;

import com.example.jwt.domain.member.member.service.AuthTokenService;
import com.example.jwt.standard.Ut;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {

    @Autowired
    private AuthTokenService authTokenService;

    @Test
    @DisplayName("AuthTokenService 생성")
    void init() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jwt 생성")
    void createToke() {
        int expireSeconds = 60 * 60 * 24 * 365;
        Key secretKey = Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

        String jwt = Ut.Jwt.createToken(secretKey, expireSeconds, Map.of("name", "paul", "age", 23));

        assertThat(jwt).isNotBlank();
        System.out.println("jwt = " + jwt);
    }
}
