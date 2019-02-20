package com.auth.security;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth.model.UserCredentials;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        Authentication authentication = null;

        try {
            String requestBody = IOUtils.toString(request.getReader());
            response.addHeader("Access-Control-Allow-Origin", "*");
            response.addHeader("Access-Control-Allow-Methods","GET, POST, PUT, DELETE");
            response.addHeader("Access-Control-Allow-Headers","Content-Type");
            response.addHeader("Access-Control-Allow-Credentials", "true");
            response.addHeader("Access-Control-Max-Age", "1209600");
            UserCredentials userCredential = objectMapper.readValue(requestBody, UserCredentials.class);

            UsernamePasswordAuthenticationToken token
                    = new UsernamePasswordAuthenticationToken(userCredential.getUsername(), userCredential.getPassword());

            setDetails(request, token);

            authentication =  this.getAuthenticationManager().authenticate(token);
        } catch(IOException exp) {
            exp.printStackTrace();
        }
        return authentication;
    }
}