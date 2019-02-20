package com.auth.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth.util.AuthorizationConstant;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;


public class AuthorizationFilter extends BasicAuthenticationFilter {

    private JwtConfig jwtConfig;
    private ObjectMapper objectMapper;
    private static final Logger logger = LogManager.getLogger(AuthorizationFilter.class);

    AuthorizationFilter(AuthenticationManager authManager,
                        JwtConfig jwtConfig,
                        ObjectMapper objectMapper) {
        super(authManager);
        this.jwtConfig = jwtConfig;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                            FilterChain chain) throws IOException, ServletException {

        String origin = request.getHeader("Origin");

        System.out.println(" Origin - " + origin);

        response.addHeader("Access-Control-Allow-Origin", origin);
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        response.addHeader("Access-Control-Max-Age", "1209600");
        response.addHeader("Access-Control-Expose-Headers", AuthorizationConstant.USER_HEADER);

        System.out.println(" Check the Method before Returning - " + request.getMethod());

        if (request.getMethod().equals("OPTIONS")) {
           //If the request is pre-flight request just return it.
            return;
        }

        String authorizationHeader = request.getHeader("Authorization");

        logger.info("authorizationHeader:" + authorizationHeader);

        if (authorizationHeader == null || !authorizationHeader.startsWith(jwtConfig.getPrefix())) {
            chain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(authorizationHeader);

        List<String> roles = new ArrayList<String>();

        for(GrantedAuthority authority: authentication.getAuthorities()) {
            if(authority.getAuthority().contains(AuthorizationConstant.ROLE)) {
                String roleData[] = authority.getAuthority().split(AuthorizationConstant.UNDER_SCORE);
                roles.add(roleData[1]);
            }
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }



    private UsernamePasswordAuthenticationToken getAuthentication(String header) {

        try {
            String token = header.replace(jwtConfig.getPrefix(), "");
            if (token != null) {
                Claims claims = Jwts.parser()
                        .setSigningKey(jwtConfig.getSecret().getBytes())
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                logger.info("username:" + username);
                if (username != null) {
                    List<String> authorities = (List<String>) claims.get(AuthorizationConstant.AUTHORITIES);
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                            username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
                    return auth;
                }
            }
        } catch (Exception exp) {
            exp.printStackTrace();
        }
        return null;
    }
}

