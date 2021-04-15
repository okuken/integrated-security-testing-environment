package okuken.iste.logic;

import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

import okuken.iste.annotations.TemplateReference;
import okuken.iste.dto.MessageDto;

public class TemplateLogic {

	private static final TemplateLogic instance = new TemplateLogic();

	private List<Method> templateReferenceMethods;
	private List<String> templateReferenceGeneralKeys;

	private TemplateLogic() {
		templateReferenceMethods = Arrays.asList(MessageDto.class.getDeclaredMethods()).stream()
				.filter(method -> method.isAnnotationPresent(TemplateReference.class))
				.collect(Collectors.toList());

		templateReferenceGeneralKeys = templateReferenceMethods.stream()
				.map(method -> method.getAnnotation(TemplateReference.class))
				.filter(TemplateReference::general)
				.map(TemplateReference::key)
				.map(this::createVelocityKey)
				.sorted()
				.collect(Collectors.toList());
	}
	public static TemplateLogic getInstance() {
		return instance;
	}

	public List<String> getTemplateReferenceGeneralKeys() {
		return templateReferenceGeneralKeys;
	}

	public String evaluateTemplate(String template, MessageDto messageDto) {
		var velocityContext = new VelocityContext();
		templateReferenceMethods.forEach(method -> {
			try {
				var key = method.getAnnotation(TemplateReference.class).key();
				var value = method.invoke(messageDto);
				velocityContext.put(key, value != null ? value.toString() : "");
			} catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		});

		StringWriter writer = new StringWriter();
		Velocity.evaluate(velocityContext, writer, "", template);
		return writer.toString();
	}

	private String createVelocityKey(String key) {
		return new StringBuilder("${")
				.append(key)
				.append("}")
				.toString();
	}

}
