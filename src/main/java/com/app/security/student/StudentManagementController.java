package com.app.security.student;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {
	
	private static final List<Student> students = Arrays.asList(new Student(1, "Srikesh"), new Student(2, "Giri"),
			new Student(3, "Praveen"), new Student(4, "Gopi"));
	
//	   @GetMapping("{studentId}")
//       public Student getStudent(@PathVariable("studentId") Integer studentId) {
//		   return students.parallelStream().
//				   filter(stu -> stu.getId().equals(studentId))
//				   .findFirst().orElseThrow(() -> new IllegalStateException("Student not found id : "+studentId ));
//	   }
	   
	   @GetMapping
	   public List<Student> getAllStudents(){
		   return students;
	   }
	   
	   @PostMapping
	   public void registerNewStudent(@RequestBody Student student) {
		   System.out.println("New Student added...");
	   }
	   
	   @DeleteMapping("{studentId}")
	   public void deleteStudent(@PathVariable("studentId") Integer id) {
		   System.out.println("Student deleted ...");
	   }
	   @PutMapping("{studentId}")
	   public void updateStudent(@PathVariable("studentId") Integer id, @RequestBody Student student) {
		   System.out.println(String.format("%s %s", id, student ));
	   }
}
