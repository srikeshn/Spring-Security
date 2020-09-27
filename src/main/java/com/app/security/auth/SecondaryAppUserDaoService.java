package com.app.security.auth;

import static com.app.security.ApplicationUserRole.*;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

@Repository("Secondary")
public class SecondaryAppUserDaoService implements ApplicationUserDao {
	
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public SecondaryAppUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers().stream().filter(
				(user) -> user.getUsername().equalsIgnoreCase(username))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers() {
		List<ApplicationUser> appUsers = Lists.newArrayList(
				new ApplicationUser(STUDENT.getGrantedAuthorities(), "srikesh", passwordEncoder.encode("password"), 
						true, true, true, true),
				new ApplicationUser(ADMIN.getGrantedAuthorities(), "Aishu", passwordEncoder.encode("password123"), 
						true, true, true, true),
				new ApplicationUser(ADMINTRAINEE.getGrantedAuthorities(), "Hero", passwordEncoder.encode("password123"), 
						true, true, true, true)
				);
		
		return appUsers;
		
	}

}
