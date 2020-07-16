/**
 * 
 */
package com.kishor.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;
import static com.kishor.security.ApplicationUserRole.ADMIN;
import static com.kishor.security.ApplicationUserRole.ADMINTRAINEE;
import static com.kishor.security.ApplicationUserRole.STUDENT;

/**
 * @author kishor kumar
 *
 */
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}

	private List<ApplicationUser> getApplicationUsers(){
	
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						ADMIN.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"kishor",
						true,
						true,
						true,
						true
				),
				new ApplicationUser(
						ADMINTRAINEE.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"mohan",
						true,
						true,
						true,
						true
				),
				new ApplicationUser(
						STUDENT.getGrantedAuthorities(),
						passwordEncoder.encode("password"),
						"nayan",
						true,
						true,
						true,
						true
				)
				
				);
	return applicationUsers;
	}
}
