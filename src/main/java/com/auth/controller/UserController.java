package com.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.auth.hibernate.entity.UserEntity;

@RestController
public class UserController {

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<String> createUser(@RequestBody UserEntity userEntity) {
		
		//validate request 
		userEntity.setPassword(new BCryptPasswordEncoder().encode(userEntity.getPassword()));
		//save user detail
		return new ResponseEntity<>(HttpStatus.CREATED);
	}
}