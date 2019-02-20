package com.auth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.hibernate.entity.UserEntity;
import com.auth.util.AuthorizationConstant;

@Service
public class UserService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//TODO:Load user from database or Active Directory
		UserEntity userEntity = new UserEntity();
		return new User(userEntity.getUsername(), userEntity.getPassword(), buildUserAuthority(userEntity));
	}
	
	private List<GrantedAuthority> buildUserAuthority(UserEntity userEntity) {		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(AuthorizationConstant.ROLE+AuthorizationConstant.UNDER_SCORE+userEntity.getRole()));
		return authorities;
	}
}