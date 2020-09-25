package com.app.security.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/students")
public class StudentController {

	private static final List<Student> students = Arrays.asList(new Student(1, "Srikesh"), new Student(2, "Giri"),
			new Student(3, "Praveen"), new Student(4, "Gopi"));

	@GetMapping(path = "{studentId}")
	public Student getStudent(@PathVariable(name = "studentId") Integer studentId) {
		return students.parallelStream().filter(student -> 
		studentId.equals(student.getId()))
				.findFirst()
				.orElseThrow(() -> new IllegalStateException("Student id : " +studentId +" Not Found") );
				
	}

}
