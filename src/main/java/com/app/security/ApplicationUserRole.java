package com.app.security;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;
import static com.app.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
	// Here Each ROLE has Authorities which we are calling as Permissions.
	//example ADMIN is a ROLE and STUDENT_READ is a authority.

	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(STUDENT_READ, COURSE_READ));
	
	private final Set<ApplicationUserPermission> permissions; 
	
	private ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
		this.permissions = permissions;
	}

	public Set<ApplicationUserPermission> getPermissions() {
		return permissions;
	}
	
	public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
		Set<SimpleGrantedAuthority> permissions = getPermissions().stream().map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
		.collect(Collectors.toSet());
		//Because when we just add ROLEs, SPring will append ROLE_ to name,
		//so now we will manually add the ROLE along with authorities in config class using this method
		permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
		return permissions;
	}

}
