package com.app.security.jwt;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

// This Class basically validates the client credentials 

public class JwtUsernameAndPasswordAuthFilter 
				extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager;
	private final JwtConfig jwtconfig;
	private final SecretKey secretKey;

	
	public JwtUsernameAndPasswordAuthFilter(AuthenticationManager authenticationManager, JwtConfig jwtconfig,
			SecretKey secretKey) {
		this.authenticationManager = authenticationManager;
		this.jwtconfig = jwtconfig;
		this.secretKey = secretKey;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		
		   try {
			UsernameAndPasswordAuthRequest authRequest = new ObjectMapper()
					.readValue(request.getInputStream(), 
							UsernameAndPasswordAuthRequest.class);
			
			Authentication authentication = new UsernamePasswordAuthenticationToken(
					authRequest.getUsername(), authRequest.getPassword());
			
			Authentication authenticate = authenticationManager.authenticate(authentication);
			return authenticate;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		
	}
	
	// THis method is called only when Credentials are valid i.e 
	//when above method(attemptAuthentication) is successful
	// Below we will create a JWT token and add it to response header
	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {
		String token = Jwts.builder()
			.setSubject(authResult.getName())
			.claim("authorities", authResult.getAuthorities())
			.setIssuedAt(new Date())
			.setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
			.signWith(secretKey)
			.compact();
		
		response.addHeader(jwtconfig.getAuthorizationHeader(), jwtconfig.getTokenPrefix()+ token);
			
	}
	
}
