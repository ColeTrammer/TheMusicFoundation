package org.leagueofcole.musicFoundationProject.service;

import org.leagueofcole.musicFoundationProject.teacher.Teacher;
import org.leagueofcole.musicFoundationProject.teacher.TeacherRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class TeacherServiceImpl {
    @Autowired
    private TeacherRepository teacherRepository;

    /*
    @Autowired
    private UserService userService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

<<<<<<< HEAD:src/main/java/org/leagueofcole/musicFoundationProject/service/TeacherServiceImpl.java
    public void save(Teacher teacher) {
        teacher.setPassword(bCryptPasswordEncoder.encode(teacher.getPassword()));
        teacher.setRoles(new HashSet<>(roleRepository.findAll()));
        teacherRepository.save(teacher);
    }

    public Teacher findByUsername(String username) {
        return teacherRepository.findByUserName(username);
    }
=======
    @Override
    public void save(Teacher user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userService.save(user);
    }

	@Override
	public Teacher findByUsername(String username) {
		return userService.findByUsername(username);
	}
	*/
}