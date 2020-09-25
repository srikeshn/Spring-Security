package com.app.security.student;

public class Student {
	
	private final Integer id;
	private final String name;
	public Student(Integer id, String name) {
		super();
		this.id = id;
		this.name = name;
	}
	public Integer getId() {
		return id;
	}
	public String getName() {
		return name;
	}
	

}
