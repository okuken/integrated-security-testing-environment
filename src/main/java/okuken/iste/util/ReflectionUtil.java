package okuken.iste.util;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ReflectionUtil {

	public static <T> void setNumberedFields(Object dest, String setterNameFormat, int startNumber, int endNumber, Class<T> fieldType, List<?> source) {
		IntStream.range(0, (endNumber - startNumber) + 1).forEach(i -> {
			try {
				dest.getClass().getMethod(String.format(setterNameFormat, i + startNumber), fieldType).invoke(dest, getIfExists(source, i));
			} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
					| NoSuchMethodException | SecurityException e) {
				throw new RuntimeException(e);
			}
		});
	}
	private static <T> T getIfExists(List<T> list, int index) {
		if(list == null) {
			return null;
		}
		if(index >= list.size()) {
			return null;
		}

		return list.get(index);
	}

	public static <T> void setNumberedFields(Object dest, String setterNameFormat, int startNumber, int endNumber, Class<T> fieldType, Object source, String getterNameFormat) {
		IntStream.range(startNumber, endNumber + 1).forEach(number -> {
			try {
				T value = getIfExists(source, getterNameFormat, number);
				dest.getClass().getMethod(String.format(setterNameFormat, number), fieldType).invoke(dest, value);
			} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
					| NoSuchMethodException | SecurityException e) {
				throw new RuntimeException(e);
			}
		});
	}
	@SuppressWarnings("unchecked")
	private static <T> T getIfExists(Object obj, String getterNameFormat, int number) {
		try {
			return (T) obj.getClass().getMethod(String.format(getterNameFormat, number)).invoke(obj);
		} catch (Exception e) {
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	public static <T> List<T> getNumberedFieldsAsList(Object obj, String getterNameFormat, int startNumber, int endNumber) {
		return IntStream.range(startNumber, endNumber + 1).mapToObj(number -> {
			return (T)getNumberedField(obj, getterNameFormat, number);
		}).collect(Collectors.toList());
	}

	@SuppressWarnings("unchecked")
	public static <T> T getNumberedField(Object obj, String getterNameFormat, int number) {
		try {
			return (T)obj.getClass().getMethod(String.format(getterNameFormat, number)).invoke(obj);
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
	}

}
