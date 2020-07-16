/**
 * 
 */
package com.kishor.auth;

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author kishor kumar
 *
 */
public class ApplicationUser implements UserDetails {

	public final Set<? extends GrantedAuthority> grantedAuthorities;
	public final String password;
	public final String username;
	public final boolean isAccountNonExpired;
	public final boolean isAccountNonLocked;
	public final boolean isCredentialsNonExpired;
	public final boolean isEnabled;
	
	
	public ApplicationUser(
			Set<? extends GrantedAuthority> grantedAuthorities,
			String password, 
			String username,
			boolean isAccountNonExpired,
			boolean isAccountNonLocked,
			boolean isCredentialsNonExpired,
			boolean isEnabled) {
		this.grantedAuthorities = grantedAuthorities;
		this.password = password;
		this.username = username;
		this.isAccountNonExpired = isAccountNonExpired;
		this.isAccountNonLocked = isAccountNonLocked;
		this.isCredentialsNonExpired = isCredentialsNonExpired;
		this.isEnabled = isEnabled;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return grantedAuthorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return isAccountNonExpired;
	}

	@Override
	public boolean isAccountNonLocked() {
		return isAccountNonLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return isCredentialsNonExpired;
	}

	@Override
	public boolean isEnabled() {
		return isEnabled;
	}

}
