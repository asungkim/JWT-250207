package com.example.jwt.domain.member.member.service;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.standard.Ut;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthTokenService {

    public String genAccessToken(Member member) {
        int expireSeconds = 60 * 60 * 24 * 365;
        Key secretKey = Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

        return Ut.Jwt.createToken(
                secretKey,
                expireSeconds,
                Map.of("id", member.getId(), "username", member.getUsername())
        );

    }

    public Map<String, Object> getPayload(SecretKey secretKey, String token) {
        Map<String, Object> payLoad = Ut.Jwt.getPayload(secretKey, token);
        if (payLoad == null) return null;

        Number idNo = (Number) payLoad.get("id");
        long id = idNo.longValue();

        String username = (String) payLoad.get("username");

        return Map.of("id", id, "username", username);
    }
}
