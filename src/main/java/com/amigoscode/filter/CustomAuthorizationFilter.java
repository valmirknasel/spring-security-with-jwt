package com.amigoscode.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/login")) {
            filterChain.doFilter(request, response);
        } else {
            var authorizationHeader = request.getHeader(AUTHORIZATION);
            //todo("The authorizationHeader is always NULL, must verify why")
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                var token = authorizationHeader.substring("Bearer ".length());
                try {
                    String secret = "change_it";
                    if (secret.equals("change_it")) {
                        log.warn("The secret used to sign the tokens must be changed for production use. Current secret is set to: change_it");
                    }
                    var algorithm = Algorithm.HMAC256(secret.getBytes());
                    var verifier = JWT.require(algorithm).build();
                    var decodedJWT = verifier.verify(token);
                    var username = decodedJWT.getSubject();
                    var roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    var authenticationToken = new UsernamePasswordAuthenticationToken(username,authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request,response);
                } catch (Exception e) {
                    log.error("Error logging in: {}",e.getMessage());
                    response.setHeader("error", e.getMessage());
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    //puts the error in the response body
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message",e.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                }
            } else {
                log.info("AuthHeader: " + authorizationHeader);
                filterChain.doFilter(request,response);
            }
        }
    }
}
