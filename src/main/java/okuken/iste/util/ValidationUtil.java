package okuken.iste.util;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

public class ValidationUtil {

	private static Validator validator;

	private static void init() {
		validator = Validation.buildDefaultValidatorFactory().getValidator();
	}

	public static <T> Optional<String> validate(T object, Class<?>... groups) {
		return validate("<html>", "<br>", "</html>", object, groups);
	}

	public static <T> Optional<String> validate(String start, String delimiter, String end, T object, Class<?>... groups) {
		var constraintViolations = validateImpl(object, groups);
		if(constraintViolations.isEmpty()) {
			return Optional.empty();
		}

		return Optional.of(new StringBuilder()
					.append(start)
					.append(constraintViolations.stream()
							.map(cv -> String.format("%s: %s", cv.getPropertyPath(), cv.getMessage()))
							.sorted()
							.collect(Collectors.joining(delimiter)))
					.append(end)
					.toString());
	}

	private static <T> Set<ConstraintViolation<T>> validateImpl(T object, Class<?>... groups) {
		if(validator == null) {
			init();
		}

		return validator.validate(object, groups);
	}

}
