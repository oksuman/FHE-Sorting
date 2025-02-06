
add_executable(app main.cpp 
		   comparison.cpp
	           encryption.cpp
	           sign.cpp
		   )

add_dependencies(app generate_coeffs_target)

