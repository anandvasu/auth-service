package com.auth.controller;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.util.AuthorizationConstant;

@RestController
@RequestMapping("/")
public class AuthorizationController {

    @GetMapping("**")
    public ResponseEntity<String> getRequest() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AuthorizationConstant.USER_HEADER, getUserHeader());
        return new ResponseEntity<>("", headers, HttpStatus.OK);
    }

    @PutMapping("**")
    public ResponseEntity<String> putRequest() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.add(AuthorizationConstant.USER_HEADER, getUserHeader());
        return new ResponseEntity<>("", headers, HttpStatus.OK);
    }

    @DeleteMapping ("**")
    public ResponseEntity<String> deleteRequest() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.add(AuthorizationConstant.USER_HEADER, getUserHeader());
        return new ResponseEntity<>("", headers, HttpStatus.OK);
    }

    @PostMapping("**")
    public ResponseEntity<String> postResquest() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.add(AuthorizationConstant.USER_HEADER, getUserHeader());
        return new ResponseEntity<>("", headers, HttpStatus.OK);
    }

    private String getUserHeader() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        List<String> roles = new ArrayList<String>();

        for(GrantedAuthority authority: authentication.getAuthorities()) {
            if(authority.getAuthority().contains(AuthorizationConstant.ROLE)) {
                String roleData[] = authority.getAuthority().split(AuthorizationConstant.UNDER_SCORE);
                roles.add(roleData[1]);
            }
        }
        String userHeader = getUserHeader(null, (String)authentication.getPrincipal(), roles);
        userHeader = userHeader + AuthorizationConstant.SIGN_KEY;
        String signature = AuthorizationConstant.SIGN_VERSION + AuthorizationConstant.HYPHEN + Base64.getEncoder().encodeToString(userHeader.getBytes());
        return getUserHeader(signature, (String)authentication.getPrincipal(), roles);
    }

    private String getUserHeader(String signature, String userName, List<String> roles) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("{");
        stringBuilder.append("\"username\":\"");
        stringBuilder.append(userName);
        stringBuilder.append("\",");
        stringBuilder.append("\"roles\":[");
        for(Iterator<String> iter = roles.iterator(); iter.hasNext();) {
            stringBuilder.append("\"");
            stringBuilder.append(iter.next());
            stringBuilder.append("\"");
            if(iter.hasNext()) {
                stringBuilder.append(",");
            }
        }
        stringBuilder.append("]");
        if(signature != null) {
            stringBuilder.append(",");
            stringBuilder.append("\"signature\":\"");
            stringBuilder.append(signature);
            stringBuilder.append("\"");
        }
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}