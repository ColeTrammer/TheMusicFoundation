package org.leagueofcole.musicFoundationProject.teacher;

import org.springframework.data.repository.CrudRepository;

public interface TeacherRepository extends CrudRepository<Teacher, Long>{
	Teacher findByUserName(String userName);
}
