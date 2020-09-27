package com.app.security.auth;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class ApplicationUser implements UserDetails {

	private static final long serialVersionUID = 1L;

	private final Set<? extends GrantedAuthority> grantedAuthorities;
	private final String username;
	private final String password;
	private final boolean isAccountNonExpired;
	private final boolean isCredentialsNonExpired;
	private final boolean isEnabled;
	private final boolean isAccountNonLocked;
	
	public ApplicationUser(Set<? extends GrantedAuthority> grantedAuthorities, 
			String username, 
			String password,
			boolean isAccountNonExpired, 
			boolean isCredentialsNonExpired, 
			boolean isEnabled,
			boolean isAccountNonLocked) {
		super();
		this.grantedAuthorities = grantedAuthorities;
		this.username = username;
		this.password = password;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
		this.isEnabled = isEnabled;
		this.isAccountNonLocked = isAccountNonLocked;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// TODO Auto-generated method stub
		return grantedAuthorities;
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return password;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return isAccountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return isAccountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return isCredentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return isEnabled;
	}

}
