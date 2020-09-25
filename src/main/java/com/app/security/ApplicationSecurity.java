package com.app.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import static com.app.security.ApplicationUserRole.*;
import static com.app.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurity extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
     public ApplicationSecurity(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	@Override
    protected void configure(HttpSecurity http) throws Exception {
    	http
    	    .csrf().disable()
    		.authorizeRequests()
    		.antMatchers("/","index","/css/*","/js/*").permitAll()
    		.antMatchers("/api/**").hasRole(STUDENT.name())
    		//The Order we are declaring AntMatchers is very important, it may break the chain when first one matches and fails criteria.
    /*    		.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
    		.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
    		.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
    		.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name()) */
    		.anyRequest()
    		.authenticated()
    		.and()
    		.httpBasic();
    }
     @Override
     @Bean
    protected UserDetailsService userDetailsService() {
    	UserDetails studentUser = User.builder().username("srikesh")
    			                  .password(passwordEncoder.encode("password"))
    			                  //.roles(STUDENT.name())
    			                  .authorities(STUDENT.getGrantedAuthorities())
    			                  .build();
    	
    	UserDetails adminUser = User.builder().username("Aishu")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
    	
    	UserDetails adminTrainee = User.builder().username("Hero")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();
    	
    	return new InMemoryUserDetailsManager(studentUser, adminUser, adminTrainee);
    	
    }
}
