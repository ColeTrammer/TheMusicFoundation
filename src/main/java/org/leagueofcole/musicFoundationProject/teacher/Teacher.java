package org.leagueofcole.musicFoundationProject.teacher;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Transient;

@Entity
@Table(name = "user")
public class Teacher {
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	private String userName;
	private String password;
<<<<<<< HEAD
	private String confirmPassword;
	private String registryCode;
	
=======
	private String passwordConfirm;

//	@ManyToMany
//	@JoinTable(name = "user_rle", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
//	private Set<Role> roles;
 Teacher(String userName, String password) {
		super();
		this.userName = userName;
		this.password = password;
	}
	Teacher() {

	}

>>>>>>> LeaguePelicans/master

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUserName() {
		return userName;
	}

	public void getUserName(String username) {
		this.userName = username;
	}

	public String getPassword() {
		return password;
	}
	public String getConfirmPassword() {
<<<<<<< HEAD
		return confirmPassword;
	}
	public String getRegistryCode() {
		return registryCode;
=======
		return "";
	}
	public String getRegistryCode() {
		return "";
>>>>>>> LeaguePelicans/master
	}

	public void setPassword(String password) {
		this.password = password;
		this.confirmPassword=confirmPassword;
		this.registryCode=registryCode;
	}

	@Transient
	public String getPasswordConfirm() {
		return passwordConfirm;
	}

	public void setPasswordConfirm(String passwordConfirm) {
		this.passwordConfirm = passwordConfirm;
	}


	
//	public Set<Role> getRoles() {
//		return roles;
//	}

	//@ManyToMany
	//@JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
	//public Set<Role> getRoles() {
		//return roles;
	//}


	//public void setRoles(Set<Role> roles) {
		//this.roles = roles;
	//}
}