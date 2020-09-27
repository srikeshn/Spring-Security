package com.app.security;

import static com.app.security.ApplicationUserRole.STUDENT;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.app.security.auth.ApplicationUserService;
import com.app.security.jwt.JwtConfig;
import com.app.security.jwt.JwtTokenVerifier;
import com.app.security.jwt.JwtUsernameAndPasswordAuthFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurity extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	
	private final ApplicationUserService userDetailsService;
	
	private final JwtConfig jwtconfig;
	
	@Autowired
	public ApplicationSecurity(PasswordEncoder passwordEncoder, ApplicationUserService userDetailsService,
			JwtConfig jwtconfig, SecretKey secretKey) {
		this.passwordEncoder = passwordEncoder;
		this.userDetailsService = userDetailsService;
		this.jwtconfig = jwtconfig;
		this.secretKey = secretKey;
	}

	private final SecretKey secretKey;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.csrf().disable() // below line will send UI XSRF token
				//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				//Since JWT are stateless in nature, we need to set below
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.addFilter(new JwtUsernameAndPasswordAuthFilter(authenticationManager(), jwtconfig, secretKey))
				.addFilterAfter(new JwtTokenVerifier(jwtconfig, secretKey), /* tokenVerifier filter will execute after : */ JwtUsernameAndPasswordAuthFilter.class)
				.authorizeRequests()
				.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
				.antMatchers("/api/**").hasRole(STUDENT.name())
				// The Order we are declaring AntMatchers is very important, it may break the
				// chain when first one matches and fails criteria.
				/*
				 * .antMatchers(HttpMethod.DELETE,
				 * "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				 * .antMatchers(HttpMethod.POST,
				 * "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				 * .antMatchers(HttpMethod.PUT,
				 * "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
				 * .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(),
				 * ADMINTRAINEE.name())
				 */
				.anyRequest()
				.authenticated();
				/*.and()
				// .httpBasic() when we replace this with below, default form login will be available
				.formLogin() // form based authentication with default login page
					.loginPage("/login").permitAll() // to mention our custom login page
					.defaultSuccessUrl("/courses", true) // we are saying to redirect to courses.html for successful login, true says force redirect.
					.usernameParameter("username") // as per html id
					.passwordParameter("password")
				// By default session ID will expire after 30 min of INACTIVITY, so if we want to remember the user then below
				.and()
				.rememberMe() // by default this option remember for 2 weeks(a cookie remember-me is set when we click remember me checkbox).
					.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21)) // we are setting remember me to 21 days expire.
					.key("securedkey") // this key is used instead of default key to make a remember-me cookie using above user and duration with md5 hashing
					.rememberMeParameter("remember-me") // as per html id.
				.and()
				.logout()
					.logoutUrl("/logout")
					//When CSRF is enabled we should use POST method for logout, Since we disabled csrf we can use GET for logout and below line adds security, delete the below line when we use csrf and POST
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.clearAuthentication(true)
					.invalidateHttpSession(true)
					.deleteCookies("JSESSIONID","remember-me")
					.logoutSuccessUrl("/login");*/
	}
	
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(userDetailsService);
		return provider;
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	

	/*
	 * @Override
	 * 
	 * @Bean protected UserDetailsService userDetailsService() { UserDetails
	 * studentUser =
	 * User.builder().username("srikesh").password(passwordEncoder.encode("password"
	 * )) // .roles(STUDENT.name())
	 * .authorities(STUDENT.getGrantedAuthorities()).build();
	 * 
	 * UserDetails adminUser =
	 * User.builder().username("Aishu").password(passwordEncoder.encode(
	 * "password123")) // .roles(ADMIN.name())
	 * .authorities(ADMIN.getGrantedAuthorities()).build();
	 * 
	 * UserDetails adminTrainee =
	 * User.builder().username("Hero").password(passwordEncoder.encode("password123"
	 * )) // .roles(ADMINTRAINEE.name())
	 * .authorities(ADMINTRAINEE.getGrantedAuthorities()).build();
	 * 
	 * return new InMemoryUserDetailsManager(studentUser, adminUser, adminTrainee);
	 * 
	 * }
	 */
}
