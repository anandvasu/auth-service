package com.auth.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.auth.model.LoginResponse;
import com.auth.service.UserService;
import com.auth.util.AuthorizationConstant;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private ObjectMapper objectMapper;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserService userService;
    private final JwtConfig jwtConfig;

    public SecurityConfig(UserService userService,
                          BCryptPasswordEncoder bCryptPasswordEncoder,
                          ObjectMapper objectMapper,
                          JwtConfig jwtConfig) {
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.objectMapper = objectMapper;
        this.jwtConfig = jwtConfig;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.cors().disable().csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/**").hasAnyAuthority("ROLE_A", "ROLE_E")
                .antMatchers(HttpMethod.PUT,"/**").hasAnyAuthority("ROLE_A", "ROLE_E")
                .antMatchers(HttpMethod.DELETE,"/**").hasAnyAuthority("ROLE_A", "ROLE_E")
                .antMatchers(HttpMethod.GET, "/**").permitAll()
                .antMatchers(HttpMethod.POST, "/example/config").hasAnyAuthority("ROLE_A", "ROLE_E")
                .antMatchers(HttpMethod.PUT, "/example/config").hasAnyAuthority("ROLE_A", "ROLE_E")
                .antMatchers(HttpMethod.PUT, "/example/config/user").hasAnyAuthority("ROLE_A")
                .and()
                .addFilterBefore(authenticationFilter(), AuthenticationFilter.class)
                .addFilterBefore(new AuthorizationFilter(authenticationManager(), jwtConfig, objectMapper), AuthorizationFilter.class)
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }


    private void loginSuccessHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        Long now = System.currentTimeMillis();
        Long expires = now + jwtConfig.getExpiration() * 1000;

        Date expireDate = new Date(expires);

        String token = Jwts.builder()
                .setSubject(authentication.getName())
                // Convert to list of strings.
                // This is important because it affects the way we get them back in the Gateway.
                .claim(AuthorizationConstant.AUTHORITIES, authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .setIssuedAt(new Date(now))
                .setExpiration(expireDate)
                .signWith(SignatureAlgorithm.HS512, jwtConfig.getSecret().getBytes())
                .compact();

        // Add token to header

        User user = (User) authentication.getPrincipal();

        String role = null;

        List<String> roles = new ArrayList<String>();

        for(GrantedAuthority authority: authentication.getAuthorities()) {
            if(authority.getAuthority().contains(AuthorizationConstant.ROLE)) {
                String roleData[] = authority.getAuthority().split(AuthorizationConstant.UNDER_SCORE);
                roles.add(roleData[1]);
            }
        }

        if(roles.size() > 1 && roles.contains(AuthorizationConstant.ROLE_ADMIN)) {
            role = AuthorizationConstant.ROLE_ADMIN;
        } else {
            role = roles.get(0);
        }


        response.setContentType("application/json");
        LoginResponse responseContent = new LoginResponse();
        responseContent.setJwt(jwtConfig.getPrefix() + token);
        responseContent.setUsername(user.getUsername());
        responseContent.setRole(role);

        response.setStatus(HttpStatus.OK.value());
        objectMapper.writeValue(response.getWriter(), responseContent);
    }

    private void loginFailureHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException e) throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        objectMapper.writeValue(response.getWriter(), "User Authentication Failed.");
    }

    @Bean
    public AuthenticationFilter authenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter
                = new AuthenticationFilter();
        authenticationFilter.setAuthenticationSuccessHandler(this::loginSuccessHandler);
        authenticationFilter.setAuthenticationFailureHandler(this::loginFailureHandler);
        authenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/user/login", "POST"));
        authenticationFilter.setAuthenticationManager(authenticationManagerBean());
        return authenticationFilter;
    }
}