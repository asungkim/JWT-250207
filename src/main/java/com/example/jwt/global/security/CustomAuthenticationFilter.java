package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final Rq rq;
    private final MemberService memberService;

    private boolean isAuthorizationHeader() {
        String authorizationHeader = rq.getHeader("Authorization");

        if (authorizationHeader == null) {
            return false;
        }

        if (!authorizationHeader.startsWith("Bearer ")) {
            return false;
        }
        return true;
    }

    private String[] getAuthTokenFromRequest() {
        if (isAuthorizationHeader()) {
            String authorizationHeader = rq.getHeader("Authorization");
            String authToken = authorizationHeader.replaceAll("Bearer ", "");

            String[] tokenBits = authToken.split(" ");

            if (tokenBits.length < 2) {
                return null;
            }

            return new String[]{tokenBits[0], tokenBits[1]};
        }

        String accessToken = rq.getValueFromCookie("accessToken");
        String apiKey = rq.getValueFromCookie("apiKey");

        if (accessToken == null || apiKey == null) {
            return null;
        }

        return new String[]{apiKey, accessToken};
    }

    private Member refreshAccessToken(String apiKey, String accessToken) {
        Optional<Member> opAccMember = memberService.getMemberByAccessToken(accessToken);
        if (opAccMember.isEmpty()) {
            Optional<Member> opApiMember = memberService.findByApiKey(apiKey);

            if (opApiMember.isEmpty()) {
                return null;
            }

            String newAccessToken = memberService.genAccessToken(opApiMember.get());
            rq.setHeader("Authorization", "Bearer " + newAccessToken);
            rq.addCookie("accessToken", newAccessToken);

            return opApiMember.get();
        }

        return opAccMember.get();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String[] tokens = getAuthTokenFromRequest();
        if (tokens == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = tokens[0];
        String accessToken = tokens[1];

        // 재발급 코드
        Member writer = refreshAccessToken(apiKey, accessToken);
        if (writer == null) {
            filterChain.doFilter(request, response);
            return;
        }

        rq.setLogin(writer);
        filterChain.doFilter(request, response);
    }
}
