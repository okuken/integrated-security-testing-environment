package okuken.iste.aspect;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;

import okuken.iste.util.BurpUtil;

@Aspect
public class ExceptionNotifierAspect {

	@Pointcut("execution(* okuken.iste.*.*(..))")
	public void loader() {}

	@Pointcut("execution(* okuken.iste.controller.Controller.*(..))")
	public void controller() {}

	@Pointcut("execution(* okuken.iste.logic.*.*(..))")
	public void logic() {}

	@AfterThrowing(value = "loader() || controller() || logic()", throwing = "e")
	public void logException(JoinPoint joinPoint, Exception e) throws Throwable {
		BurpUtil.printStderr(e);
	}

}
